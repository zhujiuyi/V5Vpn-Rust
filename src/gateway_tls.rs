use std::path::Path;

use anyhow::{Context, Result, ensure};
use native_tls::{Certificate, Protocol};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, TlsStream};
use url::Url;

pub struct GatewayTls {
    connector: TlsConnector,
    fingerprint: Option<[u8; 32]>,
}

impl GatewayTls {
    pub fn new(ca_file: Option<&Path>, fingerprint: Option<&str>) -> Result<Self> {
        let fingerprint = fingerprint.map(parse_fingerprint).transpose()?;
        let mut builder = native_tls::TlsConnector::builder();
        builder.min_protocol_version(Some(Protocol::Tlsv12));
        if let Some(path) = ca_file {
            let pem = std::fs::read(path).context("无法读取网关 CA 文件")?;
            builder.add_root_certificate(
                Certificate::from_pem(&pem).context("网关 CA 必须为 PEM 证书")?,
            );
        }
        if fingerprint.is_some() {
            // The stream remains private until open() checks the negotiated leaf.
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        Ok(Self {
            connector: TlsConnector::from(builder.build()?),
            fingerprint,
        })
    }

    pub async fn open(&self, base: &Url) -> Result<TlsStream<TcpStream>> {
        let hostname = match base.host().expect("validated gateway host") {
            url::Host::Domain(domain) => domain.to_owned(),
            url::Host::Ipv4(address) => address.to_string(),
            url::Host::Ipv6(address) => address.to_string(),
        };
        let port = base.port_or_known_default().expect("HTTPS port");
        let socket = TcpStream::connect((hostname.as_str(), port))
            .await
            .context("无法连接网关端口")?;
        let stream = self
            .connector
            .connect(&hostname, socket)
            .await
            .context("与网关建立 TLS 连接失败")?;
        if let Some(expected) = self.fingerprint {
            let leaf = stream
                .get_ref()
                .peer_certificate()?
                .context("网关未提供可核对指纹的证书")?;
            let presented: [u8; 32] = Sha256::digest(leaf.to_der()?).into();
            ensure!(presented == expected, "网关证书与确认的 SHA-256 指纹不匹配");
        }
        Ok(stream)
    }
}

pub(crate) fn parse_fingerprint(fingerprint: &str) -> Result<[u8; 32]> {
    const INVALID: &str = "网关证书指纹必须是 32 个十六进制字节，可用冒号分隔";
    let fingerprint = fingerprint.trim();
    let compact = if fingerprint.contains(':') {
        let fields: Vec<_> = fingerprint.split(':').collect();
        ensure!(
            fields.len() == 32 && fields.iter().all(|part| part.len() == 2),
            INVALID
        );
        fields.concat()
    } else {
        fingerprint.to_owned()
    };
    ensure!(
        compact.len() == 64 && compact.bytes().all(|byte| byte.is_ascii_hexdigit()),
        INVALID
    );
    let mut hash = [0; 32];
    for (offset, octet) in (0..compact.len()).step_by(2).zip(&mut hash) {
        *octet = u8::from_str_radix(&compact[offset..offset + 2], 16).context(INVALID)?;
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_compact_and_colon_separated_fingerprints() {
        let compact = "ab".repeat(32);
        let separated = vec!["AB"; 32].join(":");
        assert_eq!(parse_fingerprint(&compact).unwrap(), [0xab; 32]);
        assert_eq!(
            parse_fingerprint(&format!("  {separated}  ")).unwrap(),
            [0xab; 32]
        );
    }

    #[test]
    fn rejects_malformed_fingerprints() {
        for invalid in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "gg".repeat(32),
            vec!["a"; 32].join(":"),
            vec!["aa"; 31].join(":"),
            format!("{}:", vec!["aa"; 32].join(":")),
            "é".repeat(32),
        ] {
            assert!(parse_fingerprint(&invalid).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    #[ignore = "需要 V5VPN_TEST_GATEWAY 和 V5VPN_TEST_GATEWAY_CERT_SHA256；仅探测 TLS，不登录"]
    async fn matching_pin_connects_and_changed_pin_is_rejected() -> Result<()> {
        let gateway = Url::parse(&std::env::var("V5VPN_TEST_GATEWAY")?)?;
        let fingerprint = std::env::var("V5VPN_TEST_GATEWAY_CERT_SHA256")?;
        let matching = GatewayTls::new(None, Some(&fingerprint))?;
        let stream =
            tokio::time::timeout(std::time::Duration::from_secs(10), matching.open(&gateway))
                .await
                .context("匹配指纹的 TLS 探测超时")??;
        drop(stream);

        let mut changed = parse_fingerprint(&fingerprint)?;
        changed[0] ^= 1;
        let changed = changed
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mismatched = GatewayTls::new(None, Some(&changed))?;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            mismatched.open(&gateway),
        )
        .await
        .context("不匹配指纹的 TLS 探测超时")?;
        match result {
            Err(error) => ensure!(
                error.to_string().contains("指纹不匹配"),
                "连接未因指纹不匹配而被拒绝：{error:#}"
            ),
            Ok(_) => anyhow::bail!("不匹配的证书指纹不应获得可用的 TLS 连接"),
        }
        Ok(())
    }
}
