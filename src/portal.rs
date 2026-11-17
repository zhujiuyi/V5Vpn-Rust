use std::{net::Ipv4Addr, path::Path, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode, body::Bytes, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use reqwest::cookie::{CookieStore, Jar};
use roxmltree::{Document, Node};
use tokio::{net::TcpStream, time::timeout};
use tokio_native_tls::TlsStream;
use url::{Position, Url};
use zeroize::Zeroizing;

use crate::{
    gateway_tls::GatewayTls,
    nc_policy::{self, NcPolicy},
};

pub const USER_AGENT: &str = "LeadSec VPN Client";
const SESSION_COOKIE: &str = "VSG_SESSIONID";
const INTEGRATION: &str = "/vpn/user/portal/intergration.xml";
const AUTH_HOME: &str = "/vpn/theme/auth_home.html";
const MAX_XML_BYTES: usize = 2 * 1024 * 1024;

pub struct Gateway {
    base: Url,
    tls: GatewayTls,
    cookies: Jar,
}

struct GatewayResponse {
    status: StatusCode,
    location: Option<header::HeaderValue>,
    body: Zeroizing<Vec<u8>>,
}

pub struct Resource {
    pub map_id: String,
    pub detect_interval: Duration,
    pub heartbeat_major: u32,
}

#[derive(Clone)]
pub enum Target {
    Ipv4 { start: Ipv4Addr, end: Ipv4Addr },
    Hostname(String),
}

pub struct AuthorizedRoute {
    pub targets: Vec<Target>,
    pub tcp_ports: Vec<(u16, u16)>,
    pub map_id: String,
}

pub struct AuthorizedResources {
    pub routes: Vec<AuthorizedRoute>,
    pub detect_interval: Duration,
    pub heartbeat_major: u32,
    pub nc_policy: Option<NcPolicy>,
    pub nc_error: Option<String>,
}

impl Gateway {
    pub(crate) fn host(&self) -> &str {
        self.base
            .host_str()
            .expect("gateway host validated at construction")
    }

    pub fn new(base: Url, ca_file: Option<&Path>, fingerprint: Option<&str>) -> Result<Self> {
        ensure!(
            base.scheme() == "https"
                && base.host().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.path() == "/"
                && base.query().is_none()
                && base.fragment().is_none(),
            "网关地址必须是 HTTPS 源，例如 https://vpn.example.test:443"
        );
        Ok(Self {
            base,
            tls: GatewayTls::new(ca_file, fingerprint)?,
            cookies: Jar::default(),
        })
    }

    fn url(&self, path: &str) -> Url {
        self.base.join(path).expect("fixed gateway path")
    }

    pub async fn open_stream(&self) -> Result<TlsStream<TcpStream>> {
        self.tls.open(&self.base).await
    }

    async fn request(&self, url: Url, form: Option<&[u8]>) -> Result<GatewayResponse> {
        timeout(Duration::from_secs(20), async {
            let stream = self.open_stream().await?;
            let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
            tokio::spawn(connection);

            let mut request = Request::builder()
                .method(if form.is_some() {
                    Method::POST
                } else {
                    Method::GET
                })
                .uri(&url[Position::BeforePath..Position::AfterQuery])
                .header(
                    header::HOST,
                    &url[Position::BeforeHost..Position::AfterPort],
                )
                .header(header::CONNECTION, "close")
                .header(header::USER_AGENT, USER_AGENT);
            if let Some(cookies) = self.cookies.cookies(&url) {
                request = request.header(header::COOKIE, cookies);
            }
            if form.is_some() {
                request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            }
            let mut response = sender
                .send_request(
                    request.body(Full::new(Bytes::copy_from_slice(form.unwrap_or_default())))?,
                )
                .await?;
            self.cookies.set_cookies(
                &mut response.headers().get_all(header::SET_COOKIE).iter(),
                &url,
            );
            let status = response.status();
            let location = response.headers().get(header::LOCATION).cloned();
            let mut body = Zeroizing::new(Vec::new());
            while let Some(frame) = response.body_mut().frame().await {
                if let Ok(chunk) = frame?.into_data() {
                    ensure!(
                        body.len() + chunk.len() <= MAX_XML_BYTES,
                        "网关 XML 数据过大"
                    );
                    body.extend_from_slice(&chunk);
                }
            }
            Ok(GatewayResponse {
                status,
                location,
                body,
            })
        })
        .await
        .context("网关 HTTPS 请求超时")?
    }

    pub async fn check_version(&self) -> Result<()> {
        let response = self
            .request(self.url("/vpn/version.xml"), None)
            .await
            .context("无法通过 HTTPS 连接网关并读取协议版本")?;
        if response.status == StatusCode::FOUND
            && response
                .location
                .as_ref()
                .and_then(|value| value.to_str().ok())
                .and_then(|location| self.base.join(location).ok())
                == Some(self.url(AUTH_HOME))
        {
            // Some gateways route the anonymous version request to their login page.
            // The password and resource APIs still use the V5VPN 2.0 client contract.
            let landing = self
                .request(self.url(AUTH_HOME), None)
                .await
                .context("无法打开网关登录入口")?;
            ensure!(
                landing.status == StatusCode::OK,
                "网关登录入口返回 HTTP {}",
                landing.status.as_u16()
            );
            return Ok(());
        }
        let xml = read_xml(response).context("网关版本请求失败")?;
        let document = Document::parse(&xml).context("无法解析网关版本 XML")?;
        let version = document.root_element();
        ensure!(
            version.has_tag_name("VERSION")
                && version.attribute("major") == Some("2")
                && version.attribute("minor") == Some("0"),
            "此原型需要 V5VPN 网关协议 2.0"
        );
        Ok(())
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<()> {
        let mut form = Zeroizing::new(String::from("username="));
        append_wrapped_base64(&mut form, username);
        form.push_str("&password=");
        append_wrapped_base64(&mut form, password);
        form.push_str("&encode=1&verifycode=");
        let response = self
            .request(self.url("/vpn/user/auth/password"), Some(form.as_bytes()))
            .await
            .context("发送口令登录请求失败")?;
        let xml = read_xml(response).context("网关口令登录失败")?;
        let document = Document::parse(&xml).context("无法解析登录结果 XML")?;
        let root = document.root_element();
        ensure!(root.has_tag_name("RESPONSE"), "网关登录响应格式不匹配");
        let code = child(root, "RESULT")
            .and_then(|node| node.attribute("code"))
            .and_then(result_code)
            .context("网关未返回有效登录结果码")?;
        match code {
            0 => {}
            0x101 => bail!("网关拒绝账号或口令"),
            0x100 => bail!("网关要求修改已过期口令"),
            0x2 | 0x4 | 0x8 | 0x80 | 0x8000_0050 => bail!("网关要求额外认证，结果码 0x{code:x}"),
            _ => bail!("网关未接受口令登录，结果码 0x{code:x}"),
        }
        self.session_id()?;
        Ok(())
    }

    pub fn session_id(&self) -> Result<Zeroizing<String>> {
        let cookies = self
            .cookies
            .cookies(&self.base)
            .context("网关未签发会话 Cookie")?;
        let value = cookies
            .to_str()
            .context("网关会话 Cookie 无效")?
            .split(';')
            .find_map(|entry| {
                entry
                    .trim()
                    .split_once('=')
                    .filter(|(name, _)| *name == SESSION_COOKIE)
                    .map(|(_, value)| value)
            })
            // Some gateways issue comma-separated session IDs and expect the commas on the wire.
            .filter(|value| {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| matches!(byte, 0x21 | 0x23..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))
            })
            .context("网关未签发有效 VSG_SESSIONID")?;
        Ok(Zeroizing::new(value.to_owned()))
    }

    pub async fn resource(
        &self,
        address: Ipv4Addr,
        port: u16,
        name: Option<&str>,
    ) -> Result<Resource> {
        parse_resource(&self.fetch_resources_xml().await?, address, port, name)
    }

    pub async fn authorized_resources(&self) -> Result<AuthorizedResources> {
        parse_authorized_resources(&self.fetch_resources_xml().await?)
    }

    async fn fetch_resources_xml(&self) -> Result<Zeroizing<String>> {
        let mut url = self.url(INTEGRATION);
        url.set_query(Some("version=1.0"));
        let response = self
            .request(url, None)
            .await
            .context("读取网关授权资源失败")?;
        read_xml(response).context("读取网关授权资源失败")
    }

    pub async fn keepalive(&self, interval: Duration, major: u32) -> Result<()> {
        let mut url = self.url(INTEGRATION);
        url.set_query(Some(&format!(
            "period={}&version={major}",
            interval.as_secs()
        )));
        let response = self.request(url, None).await?;
        ensure!(
            response.status == StatusCode::OK,
            "网关拒绝会话保活（HTTP {}）",
            response.status.as_u16()
        );
        self.session_id()?;
        Ok(())
    }

    pub async fn logout(&self) -> Result<()> {
        let response = self.request(self.url("/vpn/user/logout"), None).await?;
        ensure!(
            response.status.is_success(),
            "网关退出请求返回 HTTP {}",
            response.status.as_u16()
        );
        Ok(())
    }
}

fn append_wrapped_base64(form: &mut String, input: &str) {
    let encoded = Zeroizing::new(STANDARD.encode(input));
    for line in encoded.as_bytes().chunks(76) {
        form.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        if line.len() == 76 {
            form.push_str("\r\n");
        }
    }
}

fn result_code(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

fn read_xml(response: GatewayResponse) -> Result<Zeroizing<String>> {
    ensure!(
        response.status == StatusCode::OK,
        "网关返回 HTTP {}",
        response.status.as_u16()
    );
    let bytes = response
        .body
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(&response.body);
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Ok(Zeroizing::new(text.to_owned()));
    }
    let (text, errors) = encoding_rs::GB18030.decode_without_bom_handling(bytes);
    ensure!(!errors, "网关 XML 不是有效 UTF-8 或 GB18030");
    Ok(Zeroizing::new(text.into_owned()))
}

fn child<'a, 'input>(node: Node<'a, 'input>, tag: &str) -> Option<Node<'a, 'input>> {
    node.children()
        .find(|candidate| candidate.has_tag_name(tag))
}

fn resource_list<'a, 'input>(document: &'a Document<'input>) -> Result<Node<'a, 'input>> {
    let root = document.root_element();
    ensure!(
        root.has_tag_name("INTERGRATION_INFO"),
        "网关资源响应格式不匹配"
    );
    child(root, "RESOURCE_LIST").context("网关未下发资源列表")
}

fn parse_resource(xml: &str, address: Ipv4Addr, port: u16, name: Option<&str>) -> Result<Resource> {
    let document = Document::parse(xml).map_err(|_| anyhow::anyhow!("无法解析授权资源 XML"))?;
    let list = resource_list(&document)?;
    let mut matches = list.children().filter(|&row| {
        is_authorized_tcp(row)
            && name.is_none_or(|name| row.attribute("name") == Some(name))
            && row.attribute("port").is_some_and(|spec| {
                spec.split(';')
                    .filter_map(parse_ports)
                    .any(|(start, end)| (start..=end).contains(&port))
            })
            && resource_targets(row).any(|target| {
                matches!(target, Target::Ipv4 { start, end } if (start..=end).contains(&address))
            })
    });
    let row = matches
        .next()
        .context("网关未授权所选堡垒机的 HTTPS 地址和端口")?;
    ensure!(
        matches.next().is_none(),
        "地址匹配多项资源，请用 --resource-name 指定授权资源名称"
    );
    let map_id = valid_map_id(row).context("网关未为所选资源下发有效 MapID")?;
    Ok(Resource {
        map_id: map_id.to_owned(),
        detect_interval: detect_interval(document.root_element()),
        heartbeat_major: heartbeat_major(document.root_element()),
    })
}

fn parse_authorized_resources(xml: &str) -> Result<AuthorizedResources> {
    let document = Document::parse(xml).map_err(|_| anyhow::anyhow!("无法解析授权资源 XML"))?;
    let list = resource_list(&document)?;
    let routes: Vec<_> = list
        .children()
        .filter(|&row| is_authorized_tcp(row))
        .filter_map(parse_authorized_route)
        .collect();
    let (nc_policy, nc_error) = match nc_policy::parse(list) {
        Ok(policy) => (policy, None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    if routes.is_empty() && nc_policy.is_none() {
        if let Some(error) = nc_error {
            bail!("无法读取 NC/IPsec 授权：{error}");
        }
        bail!("网关未下发可识别的已授权 TCP 或 NC 资源");
    }
    Ok(AuthorizedResources {
        routes,
        detect_interval: detect_interval(document.root_element()),
        heartbeat_major: heartbeat_major(document.root_element()),
        nc_policy,
        nc_error,
    })
}

fn parse_authorized_route(row: Node<'_, '_>) -> Option<AuthorizedRoute> {
    let map_id = valid_map_id(row)?.to_owned();
    let tcp_ports = row
        .attribute("port")?
        .split(';')
        .map(parse_ports)
        .collect::<Option<Vec<_>>>()?;
    let targets: Vec<_> = resource_targets(row).collect();
    (!targets.is_empty()).then_some(AuthorizedRoute {
        targets,
        tcp_ports,
        map_id,
    })
}

fn is_authorized_tcp(row: Node<'_, '_>) -> bool {
    row.has_tag_name("TCPUDP_RESOURCE")
        && row.attribute("status") == Some("1")
        && (row.attribute("istcp") == Some("1")
            || row
                .attribute("protocol")
                .is_some_and(|protocol| protocol.eq_ignore_ascii_case("tcp")))
}

fn valid_map_id<'a, 'input>(row: Node<'a, 'input>) -> Option<&'a str> {
    row.attribute("mapid").filter(|id| {
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    })
}

fn detect_interval(root: Node<'_, '_>) -> Duration {
    let seconds = child(root, "SESSION")
        .and_then(|node| node.attribute("detect_interval"))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=3600).contains(value))
        .unwrap_or(60);
    Duration::from_secs(seconds)
}

fn heartbeat_major(root: Node<'_, '_>) -> u32 {
    child(root, "VERSION")
        .and_then(|node| node.attribute("major"))
        .and_then(|value| value.parse().ok())
        .unwrap_or_default()
}

fn resource_targets(resource: Node<'_, '_>) -> impl Iterator<Item = Target> {
    let direct = resource
        .attribute("addr")
        .filter(|value| !value.trim().is_empty());
    let children = resource
        .children()
        .filter(move |node| direct.is_none() && node.has_tag_name("TCPUDP_IP"))
        .filter_map(|node| node.attribute("addr"));
    direct.into_iter().chain(children).filter_map(parse_target)
}

fn parse_target(value: &str) -> Option<Target> {
    let value = value.trim();
    if let Ok(address) = value.parse::<Ipv4Addr>() {
        return Some(Target::Ipv4 {
            start: address,
            end: address,
        });
    }
    if let Some((left, right)) = value.split_once('-')
        && let (Ok(start), Ok(end)) = (
            left.trim().parse::<Ipv4Addr>(),
            right.trim().parse::<Ipv4Addr>(),
        )
    {
        return (start <= end).then_some(Target::Ipv4 { start, end });
    }
    let hostname = value.strip_suffix('.').unwrap_or(value);
    if hostname.len() > 253 || !hostname.split('.').all(valid_dns_label) {
        return None;
    }
    // Reject spellings that URLs interpret as a numeric IP rather than a DNS name.
    match url::Host::parse(hostname).ok()? {
        url::Host::Domain(name) => Some(Target::Hostname(name.to_ascii_lowercase())),
        _ => None,
    }
}

fn valid_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    bytes.len() <= 63
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn parse_ports(value: &str) -> Option<(u16, u16)> {
    let parse = |part: &str| {
        let part = part.trim();
        if !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        part.parse::<u16>().ok().filter(|&port| port != 0)
    };
    let (start, end) = value.split_once('-').unwrap_or((value, value));
    let (start, end) = (parse(start)?, parse(end)?);
    (start <= end).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nc_policy::IkeId;

    #[test]
    fn accepts_original_nc_policy_without_ssl_resources() {
        let resources = parse_authorized_resources(
            r#"<INTERGRATION_INFO><RESOURCE_LIST>
                <NC_RESOURCE>
                    <IKE version="v1">
                        <SERVER ip="192.0.2.10" id="192.0.2.10" id-type="ipv4" port="1194"/>
                        <CLIENT id="Fixture client" id-type="key_id" port="500"/>
                        <Exchange mode="main"/>
                        <PSK key="Synthetic fixture"/>
                        <ISAKMP-SA><PROPOSAL><TRANSFORMS>
                            <TRANSFORM auth="psk" dh="g2" enc="aes128" hash="sha1" life-time="28800" pfs="0"/>
                        </TRANSFORMS></PROPOSAL></ISAKMP-SA>
                        <IPSEC-SA><PROPOSAL><TRANSFORMS>
                            <TRANSFORM auth="psk" dh="g2" enc="aes128" hash="sha1" life-time="3600" pfs=""/>
                        </TRANSFORMS></PROPOSAL></IPSEC-SA>
                        <DPD dpddelay="0" dpdtimeout="0"/>
                        <NAT port="0"/>
                    </IKE>
                    <PRIVATE-IP addr="198.51.100.20" netmask="255.255.255.255"/>
                    <TUNNEL status="1" negotiate-mode="1">
                        <EXTENSIONS><SECURED-ROUTES><ROUTE addr="203.0.113.5/24"/></SECURED-ROUTES></EXTENSIONS>
                    </TUNNEL>
                    <TUNNEL status="0" negotiate-mode="1">
                        <EXTENSIONS><SECURED-ROUTES><ROUTE addr="192.0.2.0/24"/></SECURED-ROUTES></EXTENSIONS>
                    </TUNNEL>
                </NC_RESOURCE>
            </RESOURCE_LIST></INTERGRATION_INFO>"#,
        )
        .unwrap();

        assert!(resources.routes.is_empty());
        assert!(resources.nc_error.is_none());
        let policy = resources.nc_policy.unwrap();
        assert_eq!(policy.routes.len(), 1);
        assert_eq!(policy.routes[0].to_string(), "203.0.113.0/24");
        assert_eq!(policy.server_port, 1194);
        assert_eq!(policy.ike_proposal, "aes128-sha1-modp1024");
        assert_eq!(policy.esp_proposal, "aes128-sha1");
        assert!(matches!(policy.client_id, IkeId::KeyId(id) if id.as_slice() == b"Fixture client"));
    }
}
