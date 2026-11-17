use std::{net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};
use zeroize::Zeroizing;

use crate::nc_policy::{IkeId, Ipv4Cidr, NcPolicy};

const IKE: &str = "v5vpn-nc";
const CHILD: &str = "v5vpn-nc-ipv4";
const KEY: &str = "v5vpn-nc-session-key";
const FRAME_LIMIT: usize = 512 * 1024;

pub(crate) struct Vici<S> {
    stream: S,
    subscribed: bool,
    usable: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Vici<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            subscribed: false,
            usable: true,
        }
    }

    pub(crate) async fn establish(&mut self, policy: &NcPolicy, peer: Ipv4Addr) -> Result<()> {
        let local = identity(&policy.client_id);
        let remote = identity(&policy.server_id);
        let mut shared = Message::packet(0, "load-shared")?;
        shared.kv("id", KEY)?;
        shared.kv("type", "IKE")?;
        shared.kv("data", policy.psk.as_slice())?;
        shared.list("owners", [local.as_bytes(), remote.as_bytes()])?;
        self.command("加载会话密钥", shared, true, Duration::from_secs(5))
            .await?;

        let connection = build_connection(policy, peer, &local, &remote)?;
        self.command("加载 NC 策略", connection, true, Duration::from_secs(5))
            .await?;

        let mut initiate = Message::packet(0, "initiate")?;
        initiate.kv("ike", IKE)?;
        initiate.kv("child", CHILD)?;
        initiate.kv("timeout", "25000")?;
        self.command("IKEv1 和 ESP 协商", initiate, true, Duration::from_secs(30))
            .await?;
        self.is_healthy(policy).await
    }

    pub(crate) async fn is_healthy(&mut self, policy: &NcPolicy) -> Result<()> {
        ensure!(self.usable, "strongSwan 控制连接已失效");
        // The caller can cancel this future after a packet has been sent.
        // Only a completed response makes the unsequenced connection reusable.
        self.usable = false;
        let result = timeout(Duration::from_secs(5), self.check_sa(policy))
            .await
            .context("查询 NC 隧道状态超时")
            .and_then(|result| result);
        self.usable = result.is_ok();
        result
    }

    async fn check_sa(&mut self, policy: &NcPolicy) -> Result<()> {
        if !self.subscribed {
            self.send(Message::packet(3, "list-sa")?).await?;
            ensure!(
                self.recv().await?.as_slice() == [5],
                "strongSwan 未确认 SA 状态订阅"
            );
            self.subscribed = true;
        }
        let mut request = Message::packet(0, "list-sas")?;
        request.kv("ike", IKE)?;
        request.kv("child", CHILD)?;
        self.send(request).await?;
        let mut installed = false;
        for _ in 0..64 {
            let bytes = self.recv().await?;
            match bytes[0] {
                1 => {
                    ensure!(installed, "未找到符合授权策略的 IKEv1/ESP 通道");
                    return Ok(());
                }
                7 => {
                    let mut payload = &bytes[1..];
                    let name = read_name(&mut payload)?;
                    if name == b"list-sa" {
                        installed |= has_authorized_sa(payload, policy)?;
                    }
                }
                _ => bail!("strongSwan 返回了意外的 SA 状态消息"),
            }
        }
        bail!("strongSwan 返回了过多的 SA 状态消息")
    }

    pub(crate) async fn stop(&mut self, _policy: &NcPolicy) -> Result<()> {
        // An interrupted command leaves no way to associate the next reply
        // with a command. Closing the disposable daemon then performs cleanup.
        if !self.usable {
            return Ok(());
        }
        let mut terminate = Message::packet(0, "terminate")?;
        terminate.kv("ike", IKE)?;
        terminate.kv("force", "yes")?;
        terminate.kv("timeout", "1500")?;
        let terminated = self
            .command("结束 NC 协商", terminate, false, Duration::from_secs(4))
            .await;

        let mut unload = Message::packet(0, "unload-conn")?;
        unload.kv("name", IKE)?;
        let unloaded = self
            .command("卸载 NC 策略", unload, false, Duration::from_secs(4))
            .await;

        let mut key = Message::packet(0, "unload-shared")?;
        key.kv("id", KEY)?;
        let key_removed = self
            .command("卸载会话密钥", key, false, Duration::from_secs(4))
            .await;
        terminated.and(unloaded).and(key_removed)
    }

    async fn command(
        &mut self,
        step: &str,
        packet: Message,
        expect_success: bool,
        delay: Duration,
    ) -> Result<()> {
        ensure!(self.usable, "strongSwan 控制连接已失效");
        self.usable = false;
        let result = timeout(delay, async {
            self.send(packet).await?;
            let response = self.recv().await?;
            ensure!(response[0] == 1, "strongSwan 未返回命令应答");
            if expect_success {
                let root = decode(&response[1..])?;
                ensure!(
                    root.value(b"success") == Some(b"yes"),
                    "strongSwan 未完成{step}"
                );
            }
            Ok(())
        })
        .await
        .with_context(|| format!("{step}超时"))
        .and_then(|result| result.with_context(|| format!("{step}失败")));
        self.usable = result.is_ok();
        result
    }

    async fn send(&mut self, packet: Message) -> Result<()> {
        ensure!(packet.0.len() <= FRAME_LIMIT, "strongSwan 请求超过大小限制");
        self.stream.write_u32(packet.0.len() as u32).await?;
        self.stream.write_all(&packet.0).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let length = self
            .stream
            .read_u32()
            .await
            .context("strongSwan 通道已关闭")? as usize;
        ensure!(
            (1..=FRAME_LIMIT).contains(&length),
            "strongSwan 消息长度无效"
        );
        let mut buffer = Zeroizing::new(vec![0; length]);
        self.stream.read_exact(&mut buffer).await?;
        Ok(buffer)
    }
}

fn identity(id: &IkeId) -> Zeroizing<String> {
    match id {
        IkeId::Ipv4(ip) => Zeroizing::new(ip.to_string()),
        IkeId::KeyId(bytes) => {
            let digits = b"0123456789abcdef";
            let mut id = Zeroizing::new(String::from("@#"));
            for &byte in bytes.iter() {
                id.push(digits[(byte >> 4) as usize] as char);
                id.push(digits[(byte & 15) as usize] as char);
            }
            id
        }
    }
}

fn build_connection(
    policy: &NcPolicy,
    peer: Ipv4Addr,
    local: &str,
    remote: &str,
) -> Result<Message> {
    let mut msg = Message::packet(0, "load-conn")?;
    msg.section(IKE, |msg| {
        msg.kv("version", "1")?;
        msg.kv("aggressive", "no")?;
        msg.kv("local_port", policy.server_port.to_string())?;
        msg.kv("remote_port", policy.server_port.to_string())?;
        msg.kv("reauth_time", policy.ike_lifetime.to_string())?;
        msg.kv("rekey_time", "0")?;
        msg.kv("keyingtries", "1")?;
        msg.list("remote_addrs", [peer.to_string()])?;
        msg.list("proposals", [policy.ike_proposal])?;
        msg.section("local", |section| {
            section.kv("auth", "psk")?;
            section.kv("id", local)
        })?;
        msg.section("remote", |section| {
            section.kv("auth", "psk")?;
            section.kv("id", remote)
        })?;
        msg.section("children", |children| {
            children.section(CHILD, |child| {
                child.kv("mode", "tunnel")?;
                child.kv("life_time", policy.esp_lifetime.to_string())?;
                child.kv(
                    "rekey_time",
                    (policy.esp_lifetime - policy.esp_lifetime / 10).to_string(),
                )?;
                child.list("esp_proposals", [policy.esp_proposal])?;
                child.list("local_ts", [format!("{}/32", policy.virtual_ip)])?;
                // Quick Mode uses an IPv4 subnet selector; platform routes enforce
                // the smaller set of destinations explicitly granted by the gateway.
                child.list("remote_ts", ["0.0.0.0/0"])
            })
        })
    })?;
    Ok(msg)
}

fn has_authorized_sa(payload: &[u8], policy: &NcPolicy) -> Result<bool> {
    let root = decode(payload)?;
    let Some(ike) = root.section(IKE.as_bytes()) else {
        return Ok(false);
    };
    if ike.value(b"state") != Some(b"ESTABLISHED") || ike.value(b"version") != Some(b"1") {
        return Ok(false);
    }
    let Some(children) = ike.section(b"child-sas") else {
        return Ok(false);
    };
    let local = policy.virtual_ip;
    Ok(children.sections.iter().any(|(_, sa)| {
        sa.value(b"name") == Some(CHILD.as_bytes())
            && sa.value(b"state") == Some(b"INSTALLED")
            && sa.value(b"protocol") == Some(b"ESP")
            && sa
                .list(b"local-ts")
                .is_some_and(|ts| ts.len() == 1 && selector(ts[0]) == Some((local, 32)))
            && sa.list(b"remote-ts").is_some_and(|ts| {
                policy.routes.iter().all(|route| {
                    ts.iter()
                        .filter_map(|item| selector(item))
                        .any(|outer| covers(outer, route))
                })
            })
    }))
}

fn selector(bytes: &[u8]) -> Option<(Ipv4Addr, u8)> {
    let value = std::str::from_utf8(bytes).ok()?;
    match value.split_once('/') {
        Some((ip, prefix)) => Some((
            ip.parse().ok()?,
            prefix.parse::<u8>().ok().filter(|p| *p <= 32)?,
        )),
        None => Some((value.parse().ok()?, 32)),
    }
}

fn covers((network, prefix): (Ipv4Addr, u8), route: &Ipv4Cidr) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    prefix <= route.prefix && (u32::from(network) & mask) == (u32::from(route.network) & mask)
}

struct Message(Zeroizing<Vec<u8>>);

impl Message {
    fn packet(kind: u8, name: &str) -> Result<Self> {
        let mut msg = Self(Zeroizing::new(vec![kind]));
        msg.name(name)?;
        Ok(msg)
    }

    fn name(&mut self, value: &str) -> Result<()> {
        self.0
            .push(value.len().try_into().context("strongSwan 字段名过长")?);
        self.0.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn value(&mut self, value: &[u8]) -> Result<()> {
        let length: u16 = value.len().try_into().context("strongSwan 字段值过长")?;
        self.0.extend_from_slice(&length.to_be_bytes());
        self.0.extend_from_slice(value);
        Ok(())
    }

    fn kv(&mut self, key: &str, value: impl AsRef<[u8]>) -> Result<()> {
        self.0.push(3);
        self.name(key)?;
        self.value(value.as_ref())
    }

    fn section(&mut self, name: &str, write: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        self.0.push(1);
        self.name(name)?;
        write(self)?;
        self.0.push(2);
        Ok(())
    }

    fn list(
        &mut self,
        name: &str,
        values: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<()> {
        self.0.push(4);
        self.name(name)?;
        for value in values {
            self.0.push(5);
            self.value(value.as_ref())?;
        }
        self.0.push(6);
        Ok(())
    }
}

#[derive(Default)]
struct Section<'a> {
    values: Vec<(&'a [u8], &'a [u8])>,
    lists: Vec<(&'a [u8], Vec<&'a [u8]>)>,
    sections: Vec<(&'a [u8], Section<'a>)>,
}

impl<'a> Section<'a> {
    fn value(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    }

    fn section(&self, name: &[u8]) -> Option<&Section<'a>> {
        self.sections
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value)
    }

    fn list(&self, name: &[u8]) -> Option<&[&'a [u8]]> {
        self.lists
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, list)| list.as_slice())
    }
}

fn decode(bytes: &[u8]) -> Result<Section<'_>> {
    parse_section(&mut &bytes[..], 0)
}

fn parse_section<'a>(bytes: &mut &'a [u8], depth: usize) -> Result<Section<'a>> {
    ensure!(depth <= 12, "strongSwan 消息嵌套过深");
    let mut section = Section::default();
    while !bytes.is_empty() {
        match take(bytes, 1)?[0] {
            1 => {
                let name = read_name(bytes)?;
                section
                    .sections
                    .push((name, parse_section(bytes, depth + 1)?));
            }
            2 if depth != 0 => return Ok(section),
            3 => section.values.push((read_name(bytes)?, read_value(bytes)?)),
            4 => {
                let name = read_name(bytes)?;
                let mut list = Vec::new();
                loop {
                    match take(bytes, 1)?[0] {
                        5 => list.push(read_value(bytes)?),
                        6 => break,
                        _ => bail!("strongSwan 列表格式无效"),
                    }
                }
                section.lists.push((name, list));
            }
            _ => bail!("strongSwan 消息格式无效"),
        }
    }
    ensure!(depth == 0, "strongSwan 消息区段不完整");
    Ok(section)
}

fn read_name<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    let count = take(bytes, 1)?[0] as usize;
    take(bytes, count)
}

fn read_value<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    let size = take(bytes, 2)?;
    take(bytes, u16::from_be_bytes([size[0], size[1]]) as usize)
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    let (value, rest) = bytes
        .split_at_checked(count)
        .context("strongSwan 消息不完整")?;
    *bytes = rest;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> NcPolicy {
        NcPolicy {
            server_id: IkeId::Ipv4(Ipv4Addr::new(192, 0, 2, 5)),
            client_id: IkeId::KeyId(Zeroizing::new(b"test-identity".to_vec())),
            server_port: 1194,
            virtual_ip: Ipv4Addr::new(198, 51, 100, 8),
            routes: vec![Ipv4Cidr {
                network: Ipv4Addr::new(203, 0, 113, 0),
                prefix: 24,
            }],
            psk: Zeroizing::new(b"synthetic-vici-fixture".to_vec()),
            ike_lifetime: 28800,
            esp_lifetime: 3600,
            ike_proposal: "aes128-sha1-modp1024",
            esp_proposal: "aes128-sha1",
        }
    }

    #[tokio::test]
    async fn establishes_checks_and_unloads_a_synthetic_nc_session() -> Result<()> {
        let (client_end, server_end) = tokio::io::duplex(8192);
        let server = async move {
            let mut server = Vici::new(server_end);
            for name in [
                "load-shared",
                "load-conn",
                "initiate",
                "list-sa",
                "list-sas",
                "terminate",
                "unload-conn",
                "unload-shared",
            ] {
                let packet = server.recv().await?;
                let mut payload = &packet[1..];
                assert_eq!(read_name(&mut payload)?, name.as_bytes());
                if name == "load-shared" {
                    assert_eq!(decode(payload)?.value(b"type"), Some(b"IKE".as_slice()));
                    assert!(decode(payload)?.value(b"data").is_some());
                }
                if name == "load-conn" {
                    let policy = decode(payload)?;
                    let ike = policy.section(IKE.as_bytes()).unwrap();
                    let esp = ike
                        .section(b"children")
                        .unwrap()
                        .section(CHILD.as_bytes())
                        .unwrap();
                    assert_eq!(ike.value(b"version"), Some(b"1".as_slice()));
                    assert_eq!(ike.value(b"remote_port"), Some(b"1194".as_slice()));
                    assert_eq!(
                        esp.list(b"remote_ts"),
                        Some([b"0.0.0.0/0".as_slice()].as_slice())
                    );
                }
                if name == "list-sa" {
                    assert_eq!(packet[0], 3);
                    server.send(Message(Zeroizing::new(vec![5]))).await?;
                    continue;
                }
                if name == "list-sas" {
                    let mut event = Message::packet(7, "list-sa")?;
                    event.section(IKE, |ike| {
                        ike.kv("version", "1")?;
                        ike.kv("state", "ESTABLISHED")?;
                        ike.section("child-sas", |children| {
                            children.section("child-1", |child| {
                                child.kv("name", CHILD)?;
                                child.kv("state", "INSTALLED")?;
                                child.kv("protocol", "ESP")?;
                                child.list("local-ts", ["198.51.100.8/32"])?;
                                child.list("remote-ts", ["0.0.0.0/0"])
                            })
                        })
                    })?;
                    server.send(event).await?;
                }
                let mut response = Message(Zeroizing::new(vec![1]));
                response.kv("success", "yes")?;
                server.send(response).await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        let client = async move {
            let mut vici = Vici::new(client_end);
            let policy = policy();
            vici.establish(&policy, Ipv4Addr::new(192, 0, 2, 9)).await?;
            vici.stop(&policy).await
        };
        tokio::try_join!(server, client)?;
        Ok(())
    }

    #[tokio::test]
    async fn canceled_health_check_closes_control_stream_without_a_second_request() -> Result<()> {
        let (client_end, server_end) = tokio::io::duplex(8192);
        let mut client = Vici::new(client_end);
        let mut server = Vici::new(server_end);
        let policy = policy();
        client.subscribed = true;
        let packet = tokio::select! {
            result = client.is_healthy(&policy) => {
                result?;
                anyhow::bail!("unexpected health response")
            }
            result = server.recv() => result?,
        };
        assert_eq!(read_name(&mut &packet[1..])?, b"list-sas");
        assert!(!client.usable);
        client.stop(&policy).await?;
        drop(client);
        assert!(server.recv().await.is_err());
        Ok(())
    }
}
