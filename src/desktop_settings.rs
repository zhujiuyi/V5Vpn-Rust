use std::{env, fs, io::Write, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DesktopSettings {
    pub profiles: Vec<GatewayProfile>,
    pub selected: usize,
    pub saved_accounts: Vec<SavedAccount>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SavedAccount {
    pub gateway: String,
    pub username: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct GatewayProfile {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub gateway_cert_sha256: String,
}

impl GatewayProfile {
    pub fn validate_certificate_pin(&self) -> Result<()> {
        let pin = self.gateway_cert_sha256.trim();
        if !pin.is_empty() {
            crate::gateway_tls::parse_fingerprint(pin)?;
        }
        Ok(())
    }
}

impl Default for GatewayProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            address: String::new(),
            port: 443,
            gateway_cert_sha256: String::new(),
        }
    }
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            profiles: vec![GatewayProfile::default()],
            selected: 0,
            saved_accounts: Vec::new(),
        }
    }
}

#[derive(Deserialize)]
struct PreviousSettings {
    gateway: String,
    #[serde(default)]
    gateway_cert_sha256: String,
}

pub fn load() -> DesktopSettings {
    let standard = directory()
        .ok()
        .and_then(|folder| fs::read(folder.join("settings.json")).ok())
        .and_then(|bytes| decode(&bytes));
    let previous = match standard {
        Some((settings, false)) => return settings,
        previous => previous.map(|(settings, _)| settings),
    };

    // The previous Windows client preferred an existing adjacent data folder.
    // Import its configured settings once, before the system copy is upgraded.
    #[cfg(windows)]
    let previous = load_portable().or(previous);
    if let Some(settings) = previous {
        let _ = save(&settings);
        settings
    } else {
        DesktopSettings::default()
    }
}

#[cfg(windows)]
fn load_portable() -> Option<DesktopSettings> {
    let executable = env::current_exe().ok()?;
    let file = executable
        .parent()?
        .join("V5VPN Data")
        .join("settings.json");
    let (settings, _) = decode(&fs::read(file).ok()?)?;
    settings
        .profiles
        .iter()
        .any(|profile| !profile.address.trim().is_empty() && profile.port != 0)
        .then_some(settings)
}

fn decode(bytes: &[u8]) -> Option<(DesktopSettings, bool)> {
    if let Ok(previous) = serde_json::from_slice::<PreviousSettings>(bytes) {
        let gateway = Url::parse(&previous.gateway).ok()?;
        let profile = GatewayProfile {
            name: "网御 VPN".into(),
            address: gateway.host_str()?.to_owned(),
            port: gateway.port_or_known_default()?,
            gateway_cert_sha256: previous.gateway_cert_sha256,
        };
        let settings = DesktopSettings {
            profiles: vec![profile],
            ..DesktopSettings::default()
        };
        return Some((settings, true));
    }
    let data: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let old_schema = data.get("saved_accounts").is_none();
    let old_resource_fields = data
        .get("profiles")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|profiles| {
            profiles.iter().any(|profile| {
                ["resource", "resource_name", "resource_spki"]
                    .iter()
                    .any(|key| profile.get(key).is_some())
            })
        });
    let mut settings: DesktopSettings = serde_json::from_value(data).ok()?;
    if settings.profiles.is_empty() {
        settings.profiles.push(GatewayProfile::default());
    }
    settings.selected = settings.selected.min(settings.profiles.len() - 1);
    Some((settings, old_schema || old_resource_fields))
}

pub fn save(settings: &DesktopSettings) -> Result<()> {
    let folder = directory()?;
    fs::create_dir_all(&folder).context("无法创建客户端设置目录")?;
    let mut temp = tempfile::NamedTempFile::new_in(&folder)?;
    serde_json::to_writer_pretty(temp.as_file_mut(), settings)?;
    temp.flush()?;
    temp.persist(folder.join("settings.json"))
        .context("无法保存客户端设置")?;
    Ok(())
}

pub fn directory() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let directory = env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let directory =
        env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Application Support"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let directory = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    Ok(directory
        .context("找不到用户设置目录")?
        .join("V5VPN Desktop"))
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn legacy_settings_upgrade_preserves_gateway_pin() {
        let source = br#"{
            "profiles": [{
                "name": "Example", "address": "vpn.example", "port": 8443,
                "gateway_cert_sha256": "example-pin"
            }],
            "selected": 0
        }"#;
        let (legacy, rewrite) = decode(source).unwrap();
        assert!(rewrite);
        assert!(legacy.saved_accounts.is_empty());

        let rewritten = serde_json::to_vec(&legacy).unwrap();
        let (settings, rewrite) = decode(&rewritten).unwrap();
        assert!(!rewrite);
        assert_eq!(settings.profiles[0].gateway_cert_sha256, "example-pin");
    }

    #[test]
    fn certificate_pin_round_trips_and_requires_valid_fingerprint() {
        let mut profile = super::GatewayProfile::default();
        assert!(profile.validate_certificate_pin().is_ok());
        profile.gateway_cert_sha256 = vec!["AB"; 32].join(":");
        let encoded = serde_json::to_vec(&profile).unwrap();
        let restored: super::GatewayProfile = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.gateway_cert_sha256, profile.gateway_cert_sha256);
        assert!(restored.validate_certificate_pin().is_ok());

        profile.gateway_cert_sha256 = "not-a-fingerprint".into();
        assert!(profile.validate_certificate_pin().is_err());
    }
}
