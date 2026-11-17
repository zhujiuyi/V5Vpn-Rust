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

fn parse_fingerprint(fingerprint: &str) -> Result<[u8; 32]> {
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
