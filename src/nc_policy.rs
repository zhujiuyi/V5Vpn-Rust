use std::{collections::BTreeSet, fmt, net::Ipv4Addr};

use anyhow::{Context, Result, ensure};
use roxmltree::Node;
use zeroize::Zeroizing;

pub enum IkeId {
    Ipv4(Ipv4Addr),
    KeyId(Zeroizing<Vec<u8>>),
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ipv4Cidr {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{}/{}", self.network, self.prefix)
    }
}

pub struct NcPolicy {
    pub server_id: IkeId,
    pub client_id: IkeId,
    pub server_port: u16,
    pub virtual_ip: Ipv4Addr,
    pub routes: Vec<Ipv4Cidr>,
    pub psk: Zeroizing<Vec<u8>>,
    pub ike_lifetime: u32,
    pub esp_lifetime: u32,
    pub ike_proposal: &'static str,
    pub esp_proposal: &'static str,
}

pub(crate) fn parse(list: Node<'_, '_>) -> Result<Option<NcPolicy>> {
    let mut authorized = list
        .children()
        .filter(|resource| resource.has_tag_name("NC_RESOURCE"))
        .filter(|resource| resource.children().any(is_authorized_tunnel));
    let Some(resource) = authorized.next() else {
        return Ok(None);
    };
    ensure!(
        authorized.next().is_none(),
        "暂不支持多个独立的 NC/IPsec 授权配置"
    );

    let mut routes = BTreeSet::new();
    for tunnel in resource
        .children()
        .filter(|&node| is_authorized_tunnel(node))
    {
        ensure!(
            tunnel.attribute("negotiate-mode") == Some("1"),
            "NC 授权隧道的协商类型不受支持"
        );
        let extensions = required_child(tunnel, "EXTENSIONS")?;
        let secured = required_child(extensions, "SECURED-ROUTES")?;
        for route in secured.children().filter(|node| node.has_tag_name("ROUTE")) {
            let address = route.attribute("addr").context("NC 授权路由缺少地址")?;
            routes.insert(parse_route(address)?);
        }
    }
    ensure!(!routes.is_empty(), "NC 授权没有可用的 IPv4 路由");

    let ike = required_child(resource, "IKE")?;
    ensure!(
        ike.attribute("version") == Some("v1"),
        "NC 网关的 IKE 版本不受支持"
    );
    ensure!(
        required_child(ike, "Exchange")?.attribute("mode") == Some("main"),
        "NC 网关的 IKE 交换模式不受支持"
    );

    let server = required_child(ike, "SERVER")?;
    let client = required_child(ike, "CLIENT")?;
    ensure!(
        server.attribute("id-type") == Some("ipv4"),
        "NC 服务器身份类型不受支持"
    );
    ensure!(
        client.attribute("id-type") == Some("key_id"),
        "NC 客户端身份类型不受支持"
    );
    // SERVER@ip is part of the XML, not necessarily the public transport peer.
    unicast_ipv4(server.attribute("ip")).context("NC 服务器地址无效")?;
    let server_id = IkeId::Ipv4(unicast_ipv4(server.attribute("id")).context("NC 服务器身份无效")?);
    let client_id = IkeId::KeyId(secret(client.attribute("id")).context("NC 客户端身份无效")?);
    let server_port = port(server, false).context("NC 服务器端口无效")?;
    let client_port = port(client, false).context("NC 客户端端口无效")?;
    let nat_port = port(required_child(ike, "NAT")?, true).context("NC NAT 端口无效")?;
    ensure!(
        (client_port == 500 || client_port == server_port) && nat_port == 0,
        "NC 策略要求当前后端未接入的 IKE 或 NAT-T 端口"
    );
    let dpd = required_child(ike, "DPD")?;
    ensure!(
        dpd.attribute("dpddelay") == Some("0") && dpd.attribute("dpdtimeout") == Some("0"),
        "NC 网关的 DPD 参数不受支持"
    );

    let (ike_proposal, ike_lifetime) = proposal(ike, "ISAKMP-SA", "0", "aes128-sha1-modp1024")?;
    let (esp_proposal, esp_lifetime) = proposal(ike, "IPSEC-SA", "", "aes128-sha1")?;
    let assigned = required_child(resource, "PRIVATE-IP")?;
    let virtual_ip = unicast_ipv4(assigned.attribute("addr")).context("NC 虚拟地址无效")?;
    ensure!(
        netmask_prefix(assigned.attribute("netmask"))? == 32,
        "当前 NC 后端要求网关下发单个 /32 虚拟地址"
    );
    let psk = secret(required_child(ike, "PSK")?.attribute("key")).context("NC 会话密钥无效")?;

    Ok(Some(NcPolicy {
        server_id,
        client_id,
        server_port,
        virtual_ip,
        routes: routes.into_iter().collect(),
        psk,
        ike_lifetime,
        esp_lifetime,
        ike_proposal,
        esp_proposal,
    }))
}

fn is_authorized_tunnel(tunnel: Node<'_, '_>) -> bool {
    tunnel.has_tag_name("TUNNEL") && tunnel.attribute("status") == Some("1")
}

fn required_child<'a, 'input>(node: Node<'a, 'input>, tag: &str) -> Result<Node<'a, 'input>> {
    let mut matches = node.children().filter(|child| child.has_tag_name(tag));
    let child = matches
        .next()
        .with_context(|| format!("NC 授权缺少 {tag} 节点"))?;
    ensure!(matches.next().is_none(), "NC 授权的 {tag} 节点重复");
    Ok(child)
}

fn proposal(
    ike: Node<'_, '_>,
    phase: &str,
    pfs: &str,
    strongswan: &'static str,
) -> Result<(&'static str, u32)> {
    let sa = required_child(ike, phase)?;
    let proposal = required_child(sa, "PROPOSAL")?;
    let transforms = required_child(proposal, "TRANSFORMS")?;
    let transform = required_child(transforms, "TRANSFORM")?;
    ensure!(
        transform.attribute("enc") == Some("aes128")
            && transform.attribute("hash") == Some("sha1")
            && transform.attribute("auth") == Some("psk")
            && transform.attribute("dh") == Some("g2")
            && transform.attribute("pfs") == Some(pfs),
        "NC 网关的 {phase} 提案不受支持"
    );
    let lifetime = transform
        .attribute("life-time")
        .and_then(decimal)
        .filter(|&seconds| seconds != 0)
        .with_context(|| format!("NC 网关的 {phase} 生命周期无效"))?;
    Ok((strongswan, lifetime))
}

fn decimal<T: std::str::FromStr>(value: &str) -> Option<T> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn port(node: Node<'_, '_>, allow_zero: bool) -> Option<u16> {
    node.attribute("port")
        .and_then(decimal)
        .filter(|&port| port != 0 || allow_zero)
}

fn unicast_ipv4(value: Option<&str>) -> Option<Ipv4Addr> {
    let address: Ipv4Addr = value?.parse().ok()?;
    (!address.is_unspecified() && !address.is_multicast() && !address.is_broadcast())
        .then_some(address)
}

fn secret(value: Option<&str>) -> Option<Zeroizing<Vec<u8>>> {
    let bytes = value?.as_bytes();
    // Known gateways send the original printable octets. Do not trim or decode
    // an identity or pre-shared key based on its appearance.
    if bytes.is_empty()
        || bytes.len() > usize::from(u16::MAX)
        || !bytes.iter().all(|byte| matches!(byte, 0x20..=0x7e))
    {
        return None;
    }
    Some(Zeroizing::new(bytes.to_vec()))
}

fn parse_route(value: &str) -> Result<Ipv4Cidr> {
    let (address, prefix) = value
        .split_once('/')
        .context("NC 路由需要使用 IPv4 CIDR 格式")?;
    let address: Ipv4Addr = address.parse().context("NC 授权路由的 IPv4 地址无效")?;
    let prefix: u8 = decimal(prefix)
        .filter(|&prefix| prefix <= 32)
        .context("NC 路由前缀无效")?;
    Ok(Ipv4Cidr {
        network: Ipv4Addr::from(u32::from(address) & mask(prefix)),
        prefix,
    })
}

fn netmask_prefix(value: Option<&str>) -> Result<u8> {
    let netmask: Ipv4Addr = value
        .context("NC 虚拟地址没有子网掩码")?
        .parse()
        .context("NC 虚拟地址的子网掩码无效")?;
    let bits = u32::from(netmask);
    let prefix = bits.leading_ones() as u8;
    ensure!(bits == mask(prefix), "NC 虚拟地址的子网掩码不连续");
    Ok(prefix)
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}
