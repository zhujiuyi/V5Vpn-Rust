use std::{
    convert::Infallible,
    io::{self, Cursor},
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{self, HeaderName, HeaderValue},
    service::service_fn,
    upgrade::OnUpgrade,
};
use hyper_util::rt::TokioIo;
use reqwest::Url;
use serde::Serialize;
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader,
    },
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
    time::timeout,
};
use zeroize::Zeroizing;

use crate::portal::{AuthorizedResources, AuthorizedRoute, Gateway, Resource, Target, USER_AGENT};

const MAX_HEADERS: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 32;
const TUNNEL_TIMEOUT: Duration = Duration::from_secs(20);
pub const PAC_PATH: &str = "/v5vpn.pac";

type ProxyBody = UnsyncBoxBody<Bytes, hyper::Error>;
type UpgradePair = (OnUpgrade, OnUpgrade);

pub struct Proxy {
    gateway: Arc<Gateway>,
    policy: RoutePolicy,
}

enum RoutePolicy {
    Single {
        resource: Resource,
        origin: Url,
        authority: String,
    },
    Assigned(AuthorizedResources),
}

impl Proxy {
    pub fn new(gateway: Arc<Gateway>, resource: Resource, origin: Url) -> Self {
        let authority = format!(
            "{}:{}",
            origin.host_str().expect("validated resource IP"),
            origin
                .port_or_known_default()
                .expect("validated resource port")
        );
        Self {
            gateway,
            policy: RoutePolicy::Single {
                resource,
                origin,
                authority,
            },
        }
    }

    pub fn for_authorized(gateway: Arc<Gateway>, resources: AuthorizedResources) -> Self {
        Self {
            gateway,
            policy: RoutePolicy::Assigned(resources),
        }
    }

    #[cfg(windows)]
    pub(crate) fn native_ipv4_hosts(&self) -> Vec<Ipv4Addr> {
        let RoutePolicy::Assigned(resources) = &self.policy else {
            return Vec::new();
        };
        let mut hosts: Vec<_> = resources
            .routes
            .iter()
            .filter(|route| !route.tcp_ports.is_empty())
            .flat_map(|route| &route.targets)
            .filter_map(|target| match target {
                Target::Ipv4 { start, end }
                    if start == end
                        && !start.is_loopback()
                        && !start.is_multicast()
                        && !start.is_link_local()
                        && !start.is_broadcast()
                        && !start.is_unspecified() =>
                {
                    Some(*start)
                }
                _ => None,
            })
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    }

    #[cfg(windows)]
    pub(crate) async fn open_native_tunnel(
        &self,
        address: Ipv4Addr,
        port: u16,
    ) -> Result<BufReader<tokio_native_tls::TlsStream<TcpStream>>> {
        let authority = format!("{address}:{port}");
        let map_id = self
            .map_id(&authority)
            .context("网关未授权该原生 TCP 连接")?;
        timeout(TUNNEL_TIMEOUT, self.open_tunnel(&authority, map_id))
            .await
            .context("网关原生 TCP 隧道建立超时")?
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        let address = listener.local_addr()?;
        ensure!(address.ip().is_loopback(), "资源代理应监听回环地址");
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept(), if tasks.len() < MAX_CONNECTIONS => {
                    let (stream, _) = accepted.context("本地资源代理无法接收连接")?;
                    let proxy = self.clone();
                    tasks.spawn(async move {
                        if let Err(error) = proxy.handle(stream, address).await {
                            eprintln!("资源连接失败：{error:#}");
                        }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }

    pub async fn keepalive(&self) -> Result<()> {
        let (interval, major) = match &self.policy {
            RoutePolicy::Single { resource, .. } => {
                (resource.detect_interval, resource.heartbeat_major)
            }
            RoutePolicy::Assigned(resources) => {
                (resources.detect_interval, resources.heartbeat_major)
            }
        };
        let wait = interval.max(Duration::from_secs(1));
        loop {
            tokio::time::sleep(wait).await;
            self.gateway
                .keepalive(interval, major)
                .await
                .context("会话保活失败，请重新登录")?;
        }
    }

    async fn handle(&self, stream: TcpStream, address: SocketAddr) -> Result<()> {
        let mut browser = BufReader::new(stream);
        let Ok(headers) = timeout(Duration::from_secs(10), read_headers(&mut browser)).await else {
            // Browsers can abandon speculative connections without sending an HTTP request.
            return Ok(());
        };
        let bytes = headers.context("无法读取浏览器代理请求头")?;
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        ensure!(
            request.parse(&bytes)?.is_complete(),
            "浏览器代理请求头不完整"
        );
        let (authority, map_id) = match (request.method, request.path) {
            (Some("GET"), Some(PAC_PATH)) => {
                return self.write_pac(browser, address).await;
            }
            (Some("CONNECT"), Some(authority)) => {
                let Some(map_id) = self.map_id(authority) else {
                    browser
                        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await?;
                    return Ok(());
                };
                (authority, map_id)
            }
            (Some(_), Some(_)) if matches!(&self.policy, RoutePolicy::Assigned(_)) => {
                return self.handle_http(browser, bytes).await;
            }
            _ => {
                browser.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                return Ok(());
            }
        };

        let upstream = timeout(TUNNEL_TIMEOUT, self.open_tunnel(authority, map_id))
            .await
            .context("网关建立隧道超时")
            .and_then(|result| result);
        let upstream = match upstream {
            Ok(tunnel) => tunnel,
            Err(error) => {
                browser.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                return Err(error);
            }
        };
        browser
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        bridge(browser, upstream).await
    }

    async fn handle_http(&self, browser: BufReader<TcpStream>, headers: Vec<u8>) -> Result<()> {
        let (read, write) = tokio::io::split(browser);
        let browser = tokio::io::join(Cursor::new(headers).chain(read), write);
        let drivers = Mutex::new(JoinSet::new());
        let (upgrade_tx, mut upgrade_rx) = mpsc::channel(1);
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .max_buf_size(MAX_HEADERS)
            .header_read_timeout(None)
            .serve_connection(
                TokioIo::new(browser),
                service_fn(|request| async {
                    let response = match self.forward_http(request, &drivers, &upgrade_tx).await {
                        Ok(response) => response,
                        Err(error) => {
                            eprintln!("HTTP 资源连接失败：{error:#}");
                            empty_response(StatusCode::BAD_GATEWAY)
                        }
                    };
                    Ok::<_, Infallible>(response)
                }),
            )
            .with_upgrades()
            .await
            .context("本地 HTTP 代理连接失败")?;

        if let Ok((client, origin)) = upgrade_rx.try_recv() {
            let (client, origin) =
                tokio::try_join!(client, origin).context("WebSocket 升级失败")?;
            bridge(TokioIo::new(client), TokioIo::new(origin)).await?;
        }
        Ok(())
    }

    async fn forward_http(
        &self,
        mut request: Request<Incoming>,
        drivers: &Mutex<JoinSet<()>>,
        upgrades: &mpsc::Sender<UpgradePair>,
    ) -> Result<Response<ProxyBody>> {
        if request.method() == Method::CONNECT {
            return Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED));
        }
        let uri = request.uri();
        let Some(scheme @ ("http" | "ws")) = uri.scheme_str() else {
            return Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED));
        };
        let Some(authority) = uri
            .authority()
            .filter(|value| !value.as_str().contains('@'))
        else {
            return Ok(empty_response(StatusCode::BAD_REQUEST));
        };
        let port = match authority.port_u16() {
            Some(port) if port != 0 => port,
            None if authority.as_str() == authority.host() => 80,
            _ => return Ok(empty_response(StatusCode::BAD_REQUEST)),
        };
        let destination = format!("{}:{port}", authority.host());
        let Some(map_id) = self.map_id(&destination) else {
            return Ok(empty_response(StatusCode::FORBIDDEN));
        };
        let websocket = request.method() == Method::GET && is_websocket_upgrade(request.headers());
        if scheme == "ws" && !websocket {
            return Ok(empty_response(StatusCode::BAD_REQUEST));
        }
        let host = HeaderValue::from_str(authority.as_str())?;
        let path = match uri.query() {
            Some(query) => format!("{}?{query}", uri.path()),
            None => uri.path().to_owned(),
        };
        let upstream = timeout(TUNNEL_TIMEOUT, self.open_tunnel(&destination, map_id))
            .await
            .context("网关建立隧道超时")??;

        let browser_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
        *request.uri_mut() = path.parse().context("无法生成源站请求路径")?;
        let nominated = strip_hop_headers(request.headers_mut(), websocket);
        request.headers_mut().insert(header::HOST, host);
        if !websocket {
            request
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        let request = request.map(|body| sanitize_body(body, nominated));
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(MAX_HEADERS)
            .handshake(TokioIo::new(upstream))
            .await
            .context("无法准备源站 HTTP 连接")?;
        drivers
            .lock()
            .expect("proxy driver lock")
            .spawn(async move {
                let _ = connection.with_upgrades().await;
            });
        let mut response = sender
            .send_request(request)
            .await
            .context("源站 HTTP 请求失败")?;
        let switched = response.status() == StatusCode::SWITCHING_PROTOCOLS;
        if switched {
            let browser_upgrade = browser_upgrade
                .filter(|_| is_websocket_upgrade(response.headers()))
                .context("源站返回了不匹配的升级响应")?;
            let origin_upgrade = hyper::upgrade::on(&mut response);
            upgrades
                .try_send((browser_upgrade, origin_upgrade))
                .context("无法接续 WebSocket 隧道")?;
        }
        let nominated = strip_hop_headers(response.headers_mut(), switched);
        Ok(response.map(|body| sanitize_body(body, nominated)))
    }

    fn map_id(&self, authority: &str) -> Option<&str> {
        match &self.policy {
            RoutePolicy::Single {
                authority: selected,
                resource,
                ..
            } => (authority == selected).then_some(resource.map_id.as_str()),
            RoutePolicy::Assigned(resources) => assigned_map_id(&resources.routes, authority),
        }
    }

    async fn open_tunnel(
        &self,
        authority: &str,
        map_id: &str,
    ) -> Result<BufReader<tokio_native_tls::TlsStream<TcpStream>>> {
        let mut upstream = BufReader::new(self.gateway.open_stream().await?);
        let session = self.gateway.session_id()?;
        let request = Zeroizing::new(format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nCookie: MapID={map_id}; VSG_SESSIONID={}\r\nUser-Agent: {USER_AGENT}\r\n\r\n",
            session.as_str()
        ));
        upstream
            .write_all(request.as_bytes())
            .await
            .context("无法向网关提交资源连接请求")?;
        upstream.flush().await?;
        let bytes = read_headers(&mut upstream)
            .await
            .context("读取网关隧道响应失败")?;
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        ensure!(
            response.parse(&bytes)?.is_complete(),
            "网关隧道响应头不完整"
        );
        ensure!(
            response.code == Some(200),
            "网关拒绝资源隧道（HTTP {}）",
            response.code.unwrap_or(0)
        );
        Ok(upstream)
    }

    async fn write_pac(&self, mut stream: BufReader<TcpStream>, address: SocketAddr) -> Result<()> {
        let script = match &self.policy {
            RoutePolicy::Single {
                origin, authority, ..
            } => {
                let host = origin.host_str().expect("validated resource IP");
                let default_port = if origin.port().is_none() {
                    format!(" || authority === \"{host}\"")
                } else {
                    String::new()
                };
                format!(
                    "function FindProxyForURL(url, host) {{\n  var authority = url.split('/')[2];\n  if ((url.indexOf(\"https://\") === 0 || url.indexOf(\"wss://\") === 0) && (authority === \"{authority}\"{default_port})) return \"PROXY {address}\";\n  return \"DIRECT\";\n}}\n"
                )
            }
            RoutePolicy::Assigned(resources) => assigned_pac(&resources.routes, address)?,
        };
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            script.len()
        );
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(script.as_bytes()).await?;
        Ok(())
    }
}

fn assigned_map_id<'a>(routes: &'a [AuthorizedRoute], authority: &str) -> Option<&'a str> {
    let (host, port) = authority.split_once(':')?;
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    let ipv4 = host.parse::<Ipv4Addr>().ok();
    routes
        .iter()
        .find(|route| {
            route
                .tcp_ports
                .iter()
                .any(|&(start, end)| port >= start && port <= end)
                && route.targets.iter().any(|target| match target {
                    Target::Ipv4 { start, end } => {
                        ipv4.is_some_and(|address| address >= *start && address <= *end)
                    }
                    Target::Hostname(name) => ipv4.is_none() && host.eq_ignore_ascii_case(name),
                })
        })
        .map(|route| route.map_id.as_str())
}

#[derive(Serialize)]
struct PacRoute<'a> {
    ipv4: Vec<(u32, u32)>,
    hosts: Vec<String>,
    ports: &'a [(u16, u16)],
}

fn assigned_pac(routes: &[AuthorizedRoute], address: SocketAddr) -> Result<String> {
    let rules: Vec<_> = routes
        .iter()
        .map(|route| {
            let mut rule = PacRoute {
                ipv4: Vec::new(),
                hosts: Vec::new(),
                ports: &route.tcp_ports,
            };
            for target in &route.targets {
                match target {
                    Target::Ipv4 { start, end } => {
                        rule.ipv4.push((u32::from(*start), u32::from(*end)))
                    }
                    Target::Hostname(name) => rule.hosts.push(name.to_ascii_lowercase()),
                }
            }
            rule
        })
        .collect();
    let rules = serde_json::to_string(&rules)?;
    Ok(format!(
        r#"function FindProxyForURL(url, host) {{
  var separator = url.indexOf("://");
  if (separator < 0) return "DIRECT";
  var scheme = url.substring(0, separator).toLowerCase();
  if (scheme !== "http" && scheme !== "https" && scheme !== "ws" && scheme !== "wss") return "DIRECT";
  var authority = url.substring(separator + 3).split(/[\/?#]/)[0];
  var parts = authority.split(":");
  if (parts.length > 2 || !/^[A-Za-z0-9.-]+$/.test(parts[0])) return "DIRECT";
  var port = scheme === "https" || scheme === "wss" ? 443 : 80;
  if (parts.length === 2) {{
    if (!/^[0-9]+$/.test(parts[1])) return "DIRECT";
    port = Number(parts[1]);
    if (port < 1 || port > 65535) return "DIRECT";
  }}
  var hostName = parts[0].toLowerCase();
  var ipv4 = ipv4Number(hostName);
  var rules = {rules};
  for (var i = 0; i < rules.length; i++) {{
    var rule = rules[i];
    if (!includesNumber(rule.ports, port)) continue;
    if (ipv4 >= 0 && includesNumber(rule.ipv4, ipv4)) return "PROXY {address}";
    if (ipv4 < 0 && rule.hosts.indexOf(hostName) !== -1) return "PROXY {address}";
  }}
  return "DIRECT";

  function includesNumber(ranges, value) {{
    for (var i = 0; i < ranges.length; i++) {{
      if (value >= ranges[i][0] && value <= ranges[i][1]) return true;
    }}
    return false;
  }}

  function ipv4Number(name) {{
    var octets = name.split(".");
    if (octets.length !== 4) return -1;
    var value = 0;
    for (var i = 0; i < octets.length; i++) {{
      if (!/^(0|[1-9][0-9]{{0,2}})$/.test(octets[i]) || Number(octets[i]) > 255) return -1;
      value = value * 256 + Number(octets[i]);
    }}
    return value;
  }}
}}
"#
    ))
}

async fn relay(
    input: &mut (impl AsyncRead + Unpin),
    output: &mut (impl AsyncWrite + Unpin),
) -> io::Result<()> {
    tokio::io::copy(input, output).await?;
    output.shutdown().await
}

async fn bridge(
    browser: impl AsyncRead + AsyncWrite + Unpin,
    upstream: impl AsyncRead + AsyncWrite + Unpin,
) -> Result<()> {
    let (mut browser_read, mut browser_write) = tokio::io::split(browser);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let upload = relay(&mut browser_read, &mut upstream_write);
    let download = relay(&mut upstream_read, &mut browser_write);
    tokio::pin!(upload, download);
    let grace = Duration::from_secs(3);
    let result = tokio::select! {
        result = &mut upload => match result {
            Ok(()) => timeout(grace, &mut download).await.unwrap_or(Ok(())),
            failed => failed,
        },
        result = &mut download => match result {
            Ok(()) => timeout(grace, &mut upload).await.unwrap_or(Ok(())),
            failed => failed,
        }
    };
    match result {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error).context("资源隧道已中断"),
    }
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers.get(header::UPGRADE).is_some_and(|value| {
        value
            .as_bytes()
            .trim_ascii()
            .eq_ignore_ascii_case(b"websocket")
    }) && connection_tokens(headers).any(|token| token.eq_ignore_ascii_case(b"upgrade"))
}

fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = &[u8]> {
    headers
        .get_all(header::CONNECTION)
        .into_iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .map(<[u8]>::trim_ascii)
}

fn strip_hop_headers(headers: &mut HeaderMap, websocket: bool) -> Vec<HeaderName> {
    let nominated: Vec<_> = connection_tokens(headers)
        .filter_map(|token| HeaderName::from_bytes(token).ok())
        .collect();
    for name in &nominated {
        headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        HeaderName::from_static("proxy-connection"),
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
    if websocket {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    }
    nominated
}

fn sanitize_body(body: Incoming, nominated: Vec<HeaderName>) -> ProxyBody {
    body.map_frame(move |mut frame| {
        if let Some(trailers) = frame.trailers_mut() {
            strip_hop_headers(trailers, false);
            for name in &nominated {
                trailers.remove(name);
            }
        }
        frame
    })
    .boxed_unsync()
}

fn empty_response(status: StatusCode) -> Response<ProxyBody> {
    let body = Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

async fn read_headers(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while bytes.len() < MAX_HEADERS {
        let remaining = (MAX_HEADERS - bytes.len()) as u64;
        let consumed = reader.take(remaining).read_until(b'\n', &mut bytes).await?;
        ensure!(consumed != 0, "连接在 HTTP 头完整到达前关闭");
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    bail!("HTTP 头超过大小限制");
}

#[cfg(all(windows, test))]
mod native_tests {
    use super::*;

    #[tokio::test]
    async fn native_targets_are_exact_and_ports_require_current_authorization() -> Result<()> {
        let host = Ipv4Addr::new(192, 0, 2, 51);
        let range_start = Ipv4Addr::new(198, 51, 100, 5);
        let gateway = Arc::new(Gateway::new(
            Url::parse("https://127.0.0.1:1")?,
            None,
            None,
        )?);
        let proxy = Proxy::for_authorized(
            gateway,
            AuthorizedResources {
                routes: vec![AuthorizedRoute {
                    targets: vec![
                        Target::Ipv4 {
                            start: host,
                            end: host,
                        },
                        Target::Ipv4 {
                            start: range_start,
                            end: Ipv4Addr::new(198, 51, 100, 7),
                        },
                    ],
                    tcp_ports: vec![(8080, 8080)],
                    map_id: "fixture".to_owned(),
                }],
                detect_interval: Duration::from_secs(60),
                heartbeat_major: 1,
                nc_policy: None,
                nc_error: None,
            },
        );
        assert_eq!(proxy.native_ipv4_hosts(), vec![host]);
        assert_eq!(proxy.map_id("192.0.2.51:8080"), Some("fixture"));
        let error = proxy.open_native_tunnel(host, 8081).await.err().unwrap();
        assert!(error.to_string().contains("网关未授权"));
        let error = proxy
            .open_native_tunnel(Ipv4Addr::new(203, 0, 113, 51), 8080)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("网关未授权"));
        Ok(())
    }
}
