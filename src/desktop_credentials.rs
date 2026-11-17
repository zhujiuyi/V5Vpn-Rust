use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

pub fn load_password(gateway: &str, username: &str) -> Result<Option<Zeroizing<String>>> {
    platform::load(&target_name(gateway, username)?, username)
}

pub fn save_password(gateway: &str, username: &str, password: &str) -> Result<()> {
    ensure!(!password.is_empty(), "不能保存空口令");
    platform::save(
        &target_name(gateway, username)?,
        username,
        password.as_bytes(),
    )
}

pub fn delete_password(gateway: &str, username: &str) -> Result<()> {
    platform::delete(&target_name(gateway, username)?, username)
}

fn target_name(gateway: &str, username: &str) -> Result<String> {
    ensure!(
        !username.trim().is_empty() && !username.contains('\0'),
        "账号无效"
    );
    let gateway = Url::parse(gateway).context("凭据对应的网关地址无效")?;
    ensure!(
        gateway.scheme() == "https"
            && gateway.host().is_some()
            && gateway.path() == "/"
            && gateway.query().is_none()
            && gateway.fragment().is_none()
            && gateway.username().is_empty()
            && gateway.password().is_none(),
        "凭据对应的网关地址无效"
    );
    let mut digest = Sha256::new();
    digest.update(gateway.as_str().as_bytes());
    digest.update([0]);
    digest.update(username.as_bytes());
    Ok(format!("V5VPN Desktop/{:x}", digest.finalize()))
}

#[cfg(any(windows, target_os = "macos"))]
fn decode_password(bytes: &[u8]) -> Result<Zeroizing<String>> {
    ensure!(!bytes.is_empty(), "凭据库中的口令为空");
    let password = std::str::from_utf8(bytes).context("凭据库中的口令编码无效")?;
    Ok(Zeroizing::new(password.to_owned()))
}

#[cfg(windows)]
mod platform {
    use std::{io, ptr::NonNull, slice};

    use anyhow::{Context, Result, ensure};
    use windows_sys::Win32::{
        Foundation::ERROR_NOT_FOUND,
        Security::Credentials::{
            CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_MAX_USERNAME_LENGTH, CRED_PERSIST_LOCAL_MACHINE,
            CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
        },
    };
    use zeroize::{Zeroize, Zeroizing};

    struct ReadCredential(NonNull<CREDENTIALW>);

    impl Drop for ReadCredential {
        fn drop(&mut self) {
            // CredReadW returns a single allocation owned by the caller.
            unsafe { CredFree(self.0.as_ptr().cast()) };
        }
    }

    pub(super) fn load(target: &str, _username: &str) -> Result<Option<Zeroizing<String>>> {
        let target = wide(target);
        let mut credential = std::ptr::null_mut();
        // The target is null-terminated, and the output pointer is valid.
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
            let error = io::Error::last_os_error();
            if not_found(&error) {
                return Ok(None);
            }
            return Err(error).context("无法从 Windows 凭据管理器读取口令");
        }
        let credential =
            ReadCredential(NonNull::new(credential).context("Windows 凭据管理器返回了空记录")?);
        let record = unsafe { credential.0.as_ref() };
        ensure!(
            !record.CredentialBlob.is_null()
                && (1..=CRED_MAX_CREDENTIAL_BLOB_SIZE).contains(&record.CredentialBlobSize),
            "Windows 凭据记录长度无效"
        );
        // The blob belongs to the CredReadW allocation and remains valid until CredFree.
        let bytes = unsafe {
            slice::from_raw_parts_mut(record.CredentialBlob, record.CredentialBlobSize as usize)
        };
        let password = super::decode_password(bytes);
        bytes.zeroize();
        password.map(Some)
    }

    pub(super) fn save(target: &str, username: &str, password: &[u8]) -> Result<()> {
        let mut target = wide(target);
        let mut username = wide(username);
        ensure!(
            username.len() - 1 <= CRED_MAX_USERNAME_LENGTH as usize,
            "账号长度超出 Windows 凭据管理器限制"
        );
        ensure!(
            password.len() <= CRED_MAX_CREDENTIAL_BLOB_SIZE as usize,
            "口令长度超出 Windows 凭据管理器限制"
        );
        let mut password = Zeroizing::new(password.to_vec());
        let record = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: password.len() as u32,
            CredentialBlob: password.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            UserName: username.as_mut_ptr(),
            ..CREDENTIALW::default()
        };
        // All borrowed fields are valid until CredWriteW returns.
        if unsafe { CredWriteW(&record, 0) } == 0 {
            return Err(io::Error::last_os_error()).context("无法将口令保存到 Windows 凭据管理器");
        }
        Ok(())
    }

    pub(super) fn delete(target: &str, _username: &str) -> Result<()> {
        let target = wide(target);
        // The target is null-terminated and remains alive until the call returns.
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            let error = io::Error::last_os_error();
            if !not_found(&error) {
                return Err(error).context("无法从 Windows 凭据管理器删除口令");
            }
        }
        Ok(())
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn not_found(error: &io::Error) -> bool {
        error.raw_os_error() == Some(ERROR_NOT_FOUND as i32)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use anyhow::{Context, Result};
    use security_framework::passwords::{
        PasswordOptions, delete_generic_password, generic_password, set_generic_password,
    };
    use zeroize::Zeroizing;

    // Security.framework's errSecItemNotFound status.
    const ITEM_NOT_FOUND: i32 = -25300;

    pub(super) fn load(target: &str, username: &str) -> Result<Option<Zeroizing<String>>> {
        match generic_password(PasswordOptions::new_generic_password(target, username)) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                super::decode_password(&bytes).map(Some)
            }
            Err(error) if error.code() == ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(error).context("无法从 macOS 钥匙串读取口令"),
        }
    }

    pub(super) fn save(target: &str, username: &str, password: &[u8]) -> Result<()> {
        set_generic_password(target, username, password).context("无法将口令保存到 macOS 钥匙串")
    }

    pub(super) fn delete(target: &str, username: &str) -> Result<()> {
        match delete_generic_password(target, username) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(error).context("无法从 macOS 钥匙串删除口令"),
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use anyhow::{Result, bail};
    use zeroize::Zeroizing;

    pub(super) fn load(_target: &str, _username: &str) -> Result<Option<Zeroizing<String>>> {
        bail!("当前系统没有可用的凭据库后端")
    }

    pub(super) fn save(_target: &str, _username: &str, _password: &[u8]) -> Result<()> {
        bail!("当前系统没有可用的凭据库后端")
    }

    pub(super) fn delete(_target: &str, _username: &str) -> Result<()> {
        bail!("当前系统没有可用的凭据库后端")
    }
}

#[cfg(test)]
mod tests {
    use super::target_name;

    #[test]
    fn key_is_scoped_to_canonical_gateway_and_account() {
        let target = target_name("https://vpn.example/", "alice").unwrap();
        assert_eq!(
            target,
            target_name("https://VPN.example:443", "alice").unwrap()
        );
        assert_ne!(
            target,
            target_name("https://vpn.example:444/", "alice").unwrap()
        );
        assert_ne!(
            target,
            target_name("https://vpn.example/", "Alice").unwrap()
        );
    }
}
