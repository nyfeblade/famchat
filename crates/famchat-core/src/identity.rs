//! Long-term cryptographic identity.
//!
//! Each user has one X25519 static keypair (the same key family Noise uses).
//! The private key is stored on disk encrypted with a key derived from a
//! passphrase via Argon2id, sealed with XChaCha20-Poly1305. Nothing sensitive
//! ever touches the disk in the clear.

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use zeroize::Zeroize;

/// The Noise parameter set used across the app. Kept here so the identity keys
/// are generated with the exact curve the handshake expects (X25519).
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// On-disk representation. Only the public key is stored in the clear.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    version: u8,
    public_key: String,    // hex
    kdf: String,           // "argon2id"
    salt: String,          // hex, Argon2 salt
    nonce: String,         // hex, XChaCha20 nonce (24 bytes)
    sealed_secret: String, // hex, encrypted private key + AEAD tag
}

/// An unlocked identity held in memory. `secret` is zeroized on drop.
pub struct Identity {
    pub public: Vec<u8>,
    secret: Vec<u8>,
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Identity {
    /// Borrow the raw private key to feed into the Noise builder.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Construct directly from raw key material (used in tests).
    #[cfg(test)]
    pub fn from_parts(public: Vec<u8>, secret: Vec<u8>) -> Self {
        Self { public, secret }
    }
}

/// Where the identity file lives (e.g. ~/.config/ciphext/identity.json).
pub fn identity_path() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "nyfe", "ciphext")
        .ok_or_else(|| anyhow!("could not determine a config directory"))?;
    Ok(dirs.config_dir().join("identity.json"))
}

/// True if an identity file already exists.
pub fn exists() -> Result<bool> {
    Ok(identity_path()?.exists())
}

/// Derive a 32-byte symmetric key from the passphrase using Argon2id.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = argon2::Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(key)
}

/// Generate a fresh identity and write it to disk, sealed with `passphrase`.
pub fn create(passphrase: &str) -> Result<Identity> {
    // Generate an X25519 keypair via snow so it matches the handshake curve.
    let builder = snow::Builder::new(NOISE_PARAMS.parse()?);
    let keypair = builder
        .generate_keypair()
        .map_err(|e| anyhow!("keypair generation failed: {e}"))?;

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut dkey = derive_key(passphrase, &salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&dkey).map_err(|e| anyhow!("cipher init failed: {e}"))?;
    dkey.zeroize();

    let sealed = cipher
        .encrypt(XNonce::from_slice(&nonce), keypair.private.as_slice())
        .map_err(|_| anyhow!("sealing private key failed"))?;

    let stored = StoredIdentity {
        version: 1,
        public_key: hex::encode(&keypair.public),
        kdf: "argon2id".into(),
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
        sealed_secret: hex::encode(&sealed),
    };

    let path = identity_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("creating config directory")?;
    }
    let json = serde_json::to_string_pretty(&stored)?;
    // Create the file already 0600 (no TOCTOU window where it is world-readable
    // between write and chmod — audit finding), then re-assert perms defensively.
    write_private(&path, json.as_bytes())?;
    restrict_permissions(&path)?;

    Ok(Identity {
        public: keypair.public,
        secret: keypair.private,
    })
}

/// Load and unseal the identity from disk using `passphrase`.
pub fn load(passphrase: &str) -> Result<Identity> {
    let path = identity_path()?;
    let json =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let stored: StoredIdentity = serde_json::from_str(&json).context("parsing identity file")?;

    if stored.version != 1 {
        return Err(anyhow!("unsupported identity version {}", stored.version));
    }

    let salt = hex::decode(&stored.salt).context("bad salt")?;
    let nonce = hex::decode(&stored.nonce).context("bad nonce")?;
    let sealed = hex::decode(&stored.sealed_secret).context("bad sealed secret")?;
    let public = hex::decode(&stored.public_key).context("bad public key")?;

    let mut dkey = derive_key(passphrase, &salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&dkey).map_err(|e| anyhow!("cipher init failed: {e}"))?;
    dkey.zeroize();

    let secret = cipher
        .decrypt(XNonce::from_slice(&nonce), sealed.as_slice())
        .map_err(|_| anyhow!("could not unlock identity — wrong passphrase?"))?;

    Ok(Identity { public, secret })
}

/// Restrict the identity file to owner-only (0600) on Unix.
#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

/// Write a file that is owner-only (0600) from the moment it is created, closing
/// the brief world-readable window of write-then-chmod.
#[cfg(unix)]
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .context("creating identity file (0600)")?;
    f.write_all(data).context("writing identity file")?;
    Ok(())
}
#[cfg(not(unix))]
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).context("writing identity file")
}

/// A human-comparable fingerprint of a public key: SHA-256, shown as
/// space-separated hex groups. Peers compare these out-of-band (in person, or
/// read aloud) to detect a man-in-the-middle.
pub fn fingerprint(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    // First 16 bytes is plenty of collision resistance for verification and
    // stays readable: 8 groups of 4 hex chars.
    digest[..16]
        .chunks(2)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase()
}
