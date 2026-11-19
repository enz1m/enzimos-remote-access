// SPDX-License-Identifier: MIT
//! User-owned sharing secrets never become login credentials or Root grants.
use crate::config;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use enzimos_platform::{Error, Result, files, json, require};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
};
use sha2::{Digest, Sha256};
use std::{io::Read, os::unix::fs::MetadataExt, path::Path};
use zeroize::Zeroizing;

fn crypto<T>(result: std::result::Result<T, openssl::error::ErrorStack>) -> Result<T> {
    result.map_err(|_| Error("desktop-certificate-operation-unavailable".into()))
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Deliberately has no Debug/Serialize implementation: passwords are private.
pub struct Identity {
    password: Zeroizing<String>,
    pub certificate_sha256_fingerprint: String,
}
impl Identity {
    pub fn tls_config(&self, directory: &Path) -> Result<Zeroizing<Vec<u8>>> {
        config::tls_config(directory, &self.password).map(Zeroizing::new)
    }
    pub fn password(&self) -> &str {
        &self.password
    }
}
fn private_read(directory: &std::fs::File, name: &str, uid: u32) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = files::open_relative(directory, Path::new(name))?;
    let before = file.metadata()?;
    require(
        before.uid() == uid
            && before.mode() & 0o7777 == 0o600
            && before.nlink() == 1
            && before.len() <= 16384,
        "desktop-private-identity-permissions",
    )?;
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file).take(16385).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    require(
        bytes.len() as u64 == before.len() && identity(&before) == identity(&after),
        "desktop-private-identity-incomplete",
    )?;
    Ok(bytes)
}
fn identity(m: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u32, u32, u64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.uid(),
        m.mode(),
        m.nlink(),
    )
}
pub fn read(directory: &Path, uid: u32) -> Result<Identity> {
    let held = files::directory(directory, Some(uid))?;
    let meta = held.metadata()?;
    require(
        meta.uid() == uid && meta.mode() & 0o777 == 0o700,
        "desktop-private-identity-permissions",
    )?;
    let certificate = private_read(&held, "certificate.pem", uid)?;
    let key = private_read(&held, "private-key.pem", uid)?;
    let credential_bytes = private_read(&held, "credential.json", uid)?;
    let mut credential = json::decode(&credential_bytes, 16384)?;
    json::fields(
        &credential,
        "schema password certificate_sha256 private_key_sha256",
    )?;
    require(
        credential["schema"].as_u64() == Some(1),
        "desktop-private-identity-invalid",
    )?;
    let password = credential
        .as_object_mut()
        .unwrap()
        .remove("password")
        .unwrap();
    let serde_json::Value::String(password) = password else {
        return Err(Error("desktop-private-identity-invalid".into()));
    };
    let password = Zeroizing::new(password);
    let _validated = Zeroizing::new(config::tls_config(directory, &password)?);
    require(
        credential["certificate_sha256"] == hash(&certificate)
            && credential["private_key_sha256"] == hash(&key),
        "desktop-private-identity-incomplete",
    )?;
    let cert = crypto(X509::from_pem(&certificate))?;
    let key = crypto(PKey::private_key_from_pem(&key))?;
    require(
        crypto(cert.public_key())?.public_eq(&key),
        "desktop-certificate-key-mismatch",
    )?;
    let now = crypto(Asn1Time::days_from_now(0))?;
    require(
        crypto(cert.not_after().compare(&now))? == std::cmp::Ordering::Greater,
        "desktop-certificate-expired",
    )?;
    let named = files::directory(directory, Some(uid))?.metadata()?;
    require(
        meta.dev() == named.dev() && meta.ino() == named.ino(),
        "desktop-private-identity-replaced",
    )?;
    Ok(Identity {
        password,
        certificate_sha256_fingerprint: hash(&crypto(cert.to_der())?),
    })
}
/// Renew certificates 30 days before they expire.
fn renewal_due(directory: &Path, uid: u32) -> Result<bool> {
    let held = files::directory(directory, Some(uid))?;
    let certificate = private_read(&held, "certificate.pem", uid)?;
    let cert = crypto(X509::from_pem(&certificate))?;
    let horizon = crypto(Asn1Time::days_from_now(30))?;
    Ok(crypto(cert.not_after().compare(&horizon))? != std::cmp::Ordering::Greater)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getuid).")]
pub fn ensure(directory: &Path, uid: u32) -> Result<Identity> {
    require(
        uid >= 1000
            && uid < u32::MAX
            && unsafe { libc::getuid() } == uid
            && unsafe { libc::geteuid() } == uid,
        "desktop-ordinary-user-identity-required",
    )?;
    let held = files::ensure_directory(directory, 0o700, uid)?;
    let _lock = files::Lock::acquire(&directory.join("identity.lock"), uid)?;
    let names = ["certificate.pem", "private-key.pem", "credential.json"];
    let mut present = 0;
    let mut ordinary = true;
    for name in names {
        match std::fs::symlink_metadata(directory.join(name)) {
            Ok(m) => {
                present += 1;
                // Links or foreign files are tampering, never something to replace.
                ordinary &= m.is_file() && m.uid() == uid && m.nlink() == 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if present > 0 {
        // A complete, valid identity that is not about to expire is reused.
        // An expired or nearly expired certificate, or a set left incomplete by
        // an interrupted first run, is replaced instead of failing every start
        // until the user deletes the directory by hand. The new fingerprint is
        // reported to the caller like a first-time identity.
        let renew = match read(directory, uid) {
            Ok(identity) if !renewal_due(directory, uid)? => return Ok(identity),
            Ok(_) => true,
            Err(error) => {
                ordinary
                    && (present < names.len()
                        || matches!(
                            error.0.as_str(),
                            "desktop-certificate-expired"
                                | "desktop-private-identity-incomplete"
                                | "desktop-certificate-key-mismatch"
                        ))
            }
        };
        if !renew {
            return read(directory, uid);
        }
        for name in names {
            match std::fs::remove_file(directory.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    let group = crypto(EcGroup::from_curve_name(Nid::X9_62_PRIME256V1))?;
    let key = crypto(PKey::from_ec_key(crypto(EcKey::generate(&group))?))?;
    let mut name = crypto(X509NameBuilder::new())?;
    crypto(name.append_entry_by_text("CN", "enzimos-remote"))?;
    let name = name.build();
    let mut cert = crypto(X509::builder())?;
    crypto(cert.set_version(2))?;
    let mut serial = crypto(BigNum::new())?;
    crypto(serial.rand(159, MsbOption::ONE, false))?;
    let serial = crypto(serial.to_asn1_integer())?;
    crypto(cert.set_serial_number(&serial))?;
    crypto(cert.set_subject_name(&name))?;
    crypto(cert.set_issuer_name(&name))?;
    crypto(cert.set_pubkey(&key))?;
    let not_before = crypto(Asn1Time::days_from_now(0))?;
    let not_after = crypto(Asn1Time::days_from_now(365))?;
    crypto(cert.set_not_before(&not_before))?;
    crypto(cert.set_not_after(&not_after))?;
    let san = crypto(
        SubjectAlternativeName::new()
            .dns("enzimos-remote")
            .build(&cert.x509v3_context(None, None)),
    )?;
    crypto(cert.append_extension(san))?;
    crypto(cert.sign(&key, MessageDigest::sha256()))?;
    let cert = cert.build();
    let certificate = crypto(cert.to_pem())?;
    let key = Zeroizing::new(crypto(key.private_key_to_pem_pkcs8())?);
    let mut random = Zeroizing::new(vec![0u8; 32]);
    crypto(openssl::rand::rand_bytes(&mut random))?;
    let password = Zeroizing::new(URL_SAFE_NO_PAD.encode(&*random));
    // Password is emitted straight into zeroizing storage, never a clonable Value.
    let credential = Zeroizing::new(format!("{{\"schema\":1,\"password\":\"{}\",\"certificate_sha256\":\"{}\",\"private_key_sha256\":\"{}\"}}", &*password, hash(&certificate), hash(&key)).into_bytes());
    let named = files::directory(directory, Some(uid))?.metadata()?;
    let original = held.metadata()?;
    require(
        named.dev() == original.dev() && named.ino() == original.ino(),
        "desktop-private-identity-replaced",
    )?;
    for (name, bytes) in [
        (names[0], certificate.as_slice()),
        (names[1], key.as_slice()),
        (names[2], credential.as_slice()),
    ] {
        files::atomic(&directory.join(name), bytes, 0o600, Some(uid), false)?;
    }
    read(directory, uid)
}
