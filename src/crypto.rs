//! Cryptographic primitives (hub_crypto.c), on RustCrypto and dalek.
//!
//! Every construction here is on the wire or on disk and must stay
//! bit-for-bit compatible with ircbot, hub_admin and the client scripts:
//!
//! * AES-256-GCM, 12-byte random IV prepended to the ciphertext, 16-byte tag
//!   carried alongside, no AAD — the shape every hub frame uses.
//! * Combined identity key: Ed25519 seed (32) || X25519 private (32);
//!   public half Ed25519 (32) || X25519 (32).
//! * Sealed box (admin login, peer handshake): eph_pub(32) || iv(12) || ct ||
//!   tag(16), key = HKDF-SHA256(X25519(eph, R), salt = eph_pub, info = label).
//! * PBKDF2-HMAC-SHA256 (100k) for the config file and the pass file.
//!
//! Secrets live in `Zeroizing` buffers and are wiped on drop.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use base64::{Engine, alphabet};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::consts::*;

pub type Key32 = Zeroizing<[u8; 32]>;

/// RAND_bytes: fill from the OS CSPRNG.
pub fn random_bytes(buf: &mut [u8]) -> bool {
    getrandom::fill(buf).is_ok()
}

/// rand() % n over the OS CSPRNG (the anti-entropy start jitter).
pub fn random_below(n: u32) -> u32 {
    let mut b = [0u8; 8];
    if n == 0 || !random_bytes(&mut b) {
        return 0;
    }
    (u64::from_le_bytes(b) % u64::from(n)) as u32
}

/// generate_uuid_v4(): random RFC 4122 v4 UUID, lower-case hex.
pub fn gen_uuid_v4() -> Option<String> {
    let mut r = [0u8; 16];
    if !random_bytes(&mut r) {
        return None;
    }
    r[6] = (r[6] & 0x0f) | 0x40;
    r[8] = (r[8] & 0x3f) | 0x80;
    let h: Vec<String> = r.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        h[0..4].concat(),
        h[4..6].concat(),
        h[6..8].concat(),
        h[8..10].concat(),
        h[10..16].concat()
    ))
}

/// Lower-case hex of `n` random bytes (purge ids, OP forward request ids).
pub fn random_hex(n: usize) -> Option<String> {
    let mut r = vec![0u8; n];
    if !random_bytes(&mut r) {
        return None;
    }
    Some(r.iter().map(|b| format!("{b:02x}")).collect())
}

/// PKCS5_PBKDF2_HMAC(SHA-256, PBKDF2_ITERATIONS): the config-file and
/// pass-file key.
pub fn derive_config_key(password: &[u8], salt: &[u8]) -> Key32 {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, PBKDF2_ITERATIONS, key.as_mut());
    key
}

fn cipher(key: &[u8]) -> Option<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).ok()
}

/// AES-256-GCM with a caller-supplied IV; returns (ciphertext, tag).
pub fn gcm_encrypt_detached(
    key: &[u8],
    iv: &[u8; GCM_IV_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Option<(Vec<u8>, [u8; GCM_TAG_LEN])> {
    let c = cipher(key)?;
    let mut buf = pt.to_vec();
    let nonce = Nonce::try_from(&iv[..]).ok()?;
    let tag = c
        .encrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into())
        .ok()?;
    let mut t = [0u8; GCM_TAG_LEN];
    t.copy_from_slice(&tag);
    Some((buf, t))
}

/// Inverse of [`gcm_encrypt_detached`]; None on a bad tag (nothing is
/// returned from an unauthenticated decryption — the C code wipes the
/// partial plaintext EVP_DecryptUpdate left behind for the same reason).
pub fn gcm_decrypt_detached(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if iv.len() != GCM_IV_LEN || tag.len() != GCM_TAG_LEN {
        return None;
    }
    let c = cipher(key)?;
    let mut buf = Zeroizing::new(ct.to_vec());
    let nonce = Nonce::try_from(iv).ok()?;
    let tag = Tag::try_from(tag).ok()?;
    c.decrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into(), &tag)
        .ok()?;
    Some(buf)
}

/// aes_gcm_encrypt(): iv(12, random) || ciphertext, with the tag returned
/// separately.  None on an RNG failure — GCM IV reuse under one key is
/// catastrophic, so there is no fallback.
pub fn aes_gcm_encrypt(plain: &[u8], key: &[u8]) -> Option<(Vec<u8>, [u8; GCM_TAG_LEN])> {
    let mut iv = [0u8; GCM_IV_LEN];
    if !random_bytes(&mut iv) {
        return None;
    }
    let (ct, tag) = gcm_encrypt_detached(key, &iv, &[], plain)?;
    let mut out = Vec::with_capacity(GCM_IV_LEN + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    Some((out, tag))
}

/// aes_gcm_decrypt(): `input` is iv(12) || ciphertext, `tag` the detached tag.
pub fn aes_gcm_decrypt(input: &[u8], key: &[u8], tag: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if input.len() < GCM_IV_LEN {
        return None;
    }
    let (iv, ct) = input.split_at(GCM_IV_LEN);
    gcm_decrypt_detached(key, iv, &[], ct, tag)
}

/// hub_crypto_hkdf_sha256: extract-and-expand into `out`.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> bool {
    if Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .is_ok()
    {
        return true;
    }
    out.zeroize();
    false
}

/// X25519(priv, peer_pub); None on an all-zero (low-order point) result,
/// which is a secret anyone can compute and must never key a session.
pub fn x25519_derive(priv_key: &[u8; 32], peer_pub: &[u8; 32]) -> Option<Key32> {
    let secret = StaticSecret::from(*priv_key);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_pub));
    if !shared.was_contributory() {
        return None;
    }
    Some(Zeroizing::new(*shared.as_bytes()))
}

pub fn x25519_public(priv_key: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*priv_key)).to_bytes()
}

fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// hub_crypto_ed25519_sign: signature over `msg` with a 32-byte seed.
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(msg).to_bytes()
}

/// hub_crypto_ed25519_verify: detached verification (a public operation).
pub fn ed25519_verify(pub_key: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(pub_key) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(&sig)).is_ok()
}

/// A fresh ephemeral X25519 keypair (the sealed-box sender half).
pub fn gen_ephemeral_x25519() -> Option<(Key32, [u8; 32])> {
    let mut priv_key = Zeroizing::new([0u8; 32]);
    if !random_bytes(priv_key.as_mut()) {
        return None;
    }
    let pub_key = x25519_public(&priv_key);
    Some((priv_key, pub_key))
}

/// hub_crypto_generate_combined_keypair: priv = ed_seed || x_priv,
/// pub = ed_pub || x_pub.
pub fn generate_combined_keypair()
-> Option<(Zeroizing<[u8; COMBINED_KEY_LEN]>, [u8; COMBINED_KEY_LEN])> {
    let mut priv_key = Zeroizing::new([0u8; COMBINED_KEY_LEN]);
    if !random_bytes(priv_key.as_mut()) {
        return None;
    }
    let pub_key = combined_pub_from_priv(&priv_key);
    Some((priv_key, pub_key))
}

/// hub_crypto_split_combined for a private key.
pub fn split_priv(priv_key: &[u8; COMBINED_KEY_LEN]) -> (Key32, Key32) {
    let mut ed = Zeroizing::new([0u8; 32]);
    let mut x = Zeroizing::new([0u8; 32]);
    ed.copy_from_slice(&priv_key[..32]);
    x.copy_from_slice(&priv_key[32..]);
    (ed, x)
}

/// hub_crypto_combined_pub_from_priv.
pub fn combined_pub_from_priv(priv_key: &[u8; COMBINED_KEY_LEN]) -> [u8; COMBINED_KEY_LEN] {
    let (ed, x) = split_priv(priv_key);
    let mut out = [0u8; COMBINED_KEY_LEN];
    out[..32].copy_from_slice(&ed25519_public(&ed));
    out[32..].copy_from_slice(&x25519_public(&x));
    out
}

/// hub_crypto_split_combined for a public key.
pub fn pub_halves(p: &[u8; COMBINED_KEY_LEN]) -> ([u8; 32], [u8; 32]) {
    let mut ed = [0u8; 32];
    let mut x = [0u8; 32];
    ed.copy_from_slice(&p[..32]);
    x.copy_from_slice(&p[32..]);
    (ed, x)
}

/// base64_encode: padding, no line breaks (OpenSSL BIO_f_base64 +
/// BIO_FLAGS_BASE64_NO_NL).
pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// base64_decode: tolerant of missing padding like the OpenSSL BIO it
/// replaces.  None for empty output or invalid characters.
/// Lowercase hex SHA-256 of a whole file, streamed 4 KB at a time — the
/// artifact integrity check for the hub's self-update.  Mirrors
/// ircbot.rs's crypto::sha256_file_hex.
pub fn sha256_file_hex(path: &str) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn b64_decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let v = Zeroizing::new(LENIENT.decode(s.as_bytes()).ok()?);
    if v.is_empty() {
        return None;
    }
    Some(v)
}

/// hub_crypto_pubkey_b64_decode: strict decode of an 88-char combined public
/// key — only the canonical base64 of exactly 64 bytes (one key, one
/// spelling: uniqueness checks and record matching compare strings), neither
/// half all zero.
pub fn pubkey_b64_decode(b64: &str) -> Option<[u8; COMBINED_KEY_LEN]> {
    let b = b64.as_bytes();
    if b.len() != COMBINED_KEY_B64 {
        return None;
    }
    for (i, &c) in b.iter().enumerate() {
        let alpha = c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
        let ok = if i >= COMBINED_KEY_B64 - 2 {
            c == b'='
        } else {
            alpha
        };
        if !ok {
            return None;
        }
    }
    let dec = STANDARD.decode(b).ok()?;
    if dec.len() != COMBINED_KEY_LEN || STANDARD.encode(&dec) != b64 {
        return None;
    }
    let mut out = [0u8; COMBINED_KEY_LEN];
    out.copy_from_slice(&dec);
    if out[..32].iter().all(|&x| x == 0) || out[32..].iter().all(|&x| x == 0) {
        return None;
    }
    Some(out)
}

/// hub_crypto_key_fingerprint: "ab12:cd34:ef56:7890", the first 8 bytes of
/// SHA-256(pub64).
pub fn key_fingerprint(pub_key: &[u8; COMBINED_KEY_LEN]) -> String {
    let h = Sha256::digest(pub_key);
    format!(
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}

/// hub_crypto_key_fingerprint_b64: fingerprint of an 88-char key string, or
/// "(no key)" / "(bad key)".
pub fn key_fingerprint_b64(b64: &str) -> String {
    if b64.is_empty() {
        return "(no key)".to_string();
    }
    match pubkey_b64_decode(b64) {
        Some(raw) => key_fingerprint(&raw),
        None => "(bad key)".to_string(),
    }
}

/// hub_seal_send: seal `plain` to a recipient X25519 public key under an
/// ephemeral key.  Returns (frame, session_key); the frame is
/// eph_pub(32) || iv(12) || ct || tag(16) and the session key is what both
/// sides use for every frame afterwards.
pub fn seal_send(
    recipient_x_pub: &[u8; 32],
    plain: &[u8],
    info: &[u8],
) -> Option<(Vec<u8>, Key32)> {
    let (eph_priv, eph_pub) = gen_ephemeral_x25519()?;
    let shared = x25519_derive(&eph_priv, recipient_x_pub)?;
    let mut session_key = Zeroizing::new([0u8; 32]);
    if !hkdf_sha256(shared.as_ref(), &eph_pub, info, session_key.as_mut()) {
        return None;
    }
    let (body, tag) = aes_gcm_encrypt(plain, session_key.as_ref())?;
    let mut out = Vec::with_capacity(32 + body.len() + GCM_TAG_LEN);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&body);
    out.extend_from_slice(&tag);
    Some((out, session_key))
}

/// hub_seal_open: inverse of [`seal_send`] for the holder of `r_x_priv`.
/// Returns (plaintext, session_key).
pub fn seal_open(
    r_x_priv: &[u8; 32],
    frame: &[u8],
    info: &[u8],
) -> Option<(Zeroizing<Vec<u8>>, Key32)> {
    if frame.len() < 32 + GCM_IV_LEN + GCM_TAG_LEN {
        return None;
    }
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&frame[..32]);
    let body = &frame[32..frame.len() - GCM_TAG_LEN];
    let tag = &frame[frame.len() - GCM_TAG_LEN..];
    let shared = x25519_derive(r_x_priv, &eph_pub)?;
    let mut session_key = Zeroizing::new([0u8; 32]);
    if !hkdf_sha256(shared.as_ref(), &eph_pub, info, session_key.as_mut()) {
        return None;
    }
    let pt = aes_gcm_decrypt(body, session_key.as_ref(), tag)?;
    Some((pt, session_key))
}

/// CRYPTO_memcmp: constant-time equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// secure_wipe: zero a byte buffer in place.
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let (frame, tag) = aes_gcm_encrypt(b"hello", &key).unwrap();
        assert_eq!(frame.len(), GCM_IV_LEN + 5);
        assert_eq!(
            aes_gcm_decrypt(&frame, &key, &tag).unwrap().as_slice(),
            b"hello"
        );
        let mut bad = frame.clone();
        bad[GCM_IV_LEN] ^= 1;
        assert!(aes_gcm_decrypt(&bad, &key, &tag).is_none());
        assert!(aes_gcm_decrypt(&frame[..GCM_IV_LEN - 1], &key, &tag).is_none());
    }

    #[test]
    fn seal_roundtrip() {
        let (priv64, pub64) = generate_combined_keypair().unwrap();
        let (_, x_priv) = split_priv(&priv64);
        let (_, x_pub) = pub_halves(&pub64);
        let info = b"irchub-peer-session-v1";
        let (frame, k1) = seal_send(&x_pub, b"HUBv3|uuid|7000", info).unwrap();
        let (pt, k2) = seal_open(&x_priv, &frame, info).unwrap();
        assert_eq!(pt.as_slice(), b"HUBv3|uuid|7000");
        assert_eq!(k1.as_ref(), k2.as_ref());
        // A different info label derives a different key, so the tag fails.
        assert!(seal_open(&x_priv, &frame, b"irchub-admin-session-v2").is_none());
    }

    #[test]
    fn pubkey_decode_is_strict() {
        let (_, p) = generate_combined_keypair().unwrap();
        let b = b64_encode(&p);
        assert_eq!(pubkey_b64_decode(&b), Some(p));
        assert!(pubkey_b64_decode(&b[..87]).is_none());
        assert!(pubkey_b64_decode(&b64_encode(&[0u8; 64])).is_none());
        assert_eq!(key_fingerprint(&p).len(), KEY_FP_LEN);
        assert_eq!(key_fingerprint_b64(""), "(no key)");
        assert_eq!(key_fingerprint_b64("nope"), "(bad key)");
    }

    #[test]
    fn x25519_rejects_low_order() {
        assert!(x25519_derive(&[1u8; 32], &[0u8; 32]).is_none());
    }

    #[test]
    fn uuid_shape() {
        let u = gen_uuid_v4().unwrap();
        assert!(crate::cstr::is_uuid(&u));
        assert_eq!(&u[14..15], "4");
    }

    #[test]
    fn ed25519_rfc8032_vector1() {
        // RFC 8032 section 7.1, TEST 1 (empty message).
        let seed: [u8; 32] =
            hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pk = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(ed25519_public(&seed), pk);
        let sig = ed25519_sign(&seed, b"");
        assert!(ed25519_verify(&pk, b"", &sig));
        assert_eq!(sig[..8], [0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72]);
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for (i, b) in o.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    }
}
