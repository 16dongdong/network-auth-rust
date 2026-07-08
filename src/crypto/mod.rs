use aes::Aes256;
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use p256::{
    ecdsa::{Signature as P256Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use rand::{RngCore, rngs::OsRng};
use rsa::{
    Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
const EC_PUBLIC_KEY_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const PRIME256V1_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct GcmPayload {
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

pub struct SignatureInput<'a> {
    pub method: &'a str,
    pub route: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKeyPair {
    pub public_key: String,
    pub private_key_cipher: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCryptoAlgorithm {
    RsaOaepAes256Gcm,
    RsaOaepAes128Gcm,
    RsaPkcs1Aes256Gcm,
}

impl ClientCryptoAlgorithm {
    pub const DEFAULT_NAME: &'static str = "rsa_oaep_aes_256_gcm";

    pub fn normalize(value: &str) -> Result<Self, AppError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "rsa_oaep_aes_256_gcm" => Ok(Self::RsaOaepAes256Gcm),
            "rsa_oaep_aes_128_gcm" => Ok(Self::RsaOaepAes128Gcm),
            "rsa_pkcs1_aes_256_gcm" => Ok(Self::RsaPkcs1Aes256Gcm),
            _ => Err(AppError::UnsupportedClientCrypto),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::RsaOaepAes256Gcm => Self::DEFAULT_NAME,
            Self::RsaOaepAes128Gcm => "rsa_oaep_aes_128_gcm",
            Self::RsaPkcs1Aes256Gcm => "rsa_pkcs1_aes_256_gcm",
        }
    }

    pub fn key_bytes(self) -> usize {
        match self {
            Self::RsaOaepAes256Gcm | Self::RsaPkcs1Aes256Gcm => 32,
            Self::RsaOaepAes128Gcm => 16,
        }
    }
}

pub fn token(byte_count: usize) -> String {
    let mut bytes = vec![0_u8; byte_count];
    OsRng.fill_bytes(&mut bytes);
    encode_base64_url(&bytes)
}

pub fn sha256_hex(value: &str) -> String {
    sha256_hex_bytes(value.as_bytes())
}

pub fn sha256_hex_bytes(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

pub fn encode_base64_url(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

pub fn decode_base64_url(encoded: &str) -> Result<Vec<u8>, AppError> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::CryptoError("Base64Url 编码格式错误"))
}

pub fn encrypt_protected_text(plaintext: &str, system_key: &str) -> Result<String, AppError> {
    let mut iv = [0_u8; 16];
    OsRng.fill_bytes(&mut iv);
    encrypt_protected_text_with_iv(plaintext, system_key, &iv)
}

pub fn decrypt_protected_text(encoded: &str, system_key: &str) -> Result<String, AppError> {
    let raw = decode_base64_url(encoded)?;
    if raw.len() < 49 {
        return Err(AppError::CryptoError("受保护文本密文格式错误"));
    }

    let key = protected_key(system_key);
    let iv = &raw[..16];
    let mac = &raw[16..48];
    let ciphertext = &raw[48..];
    assert_protected_text_mac(&key, iv, ciphertext, mac)?;
    decrypt_cbc_text(&key, iv, ciphertext)
}

pub fn encrypt_gcm(plaintext: &str, raw_key: &[u8], aad: &str) -> Result<GcmPayload, AppError> {
    let mut iv = [0_u8; 12];
    OsRng.fill_bytes(&mut iv);
    encrypt_gcm_with_iv(plaintext, raw_key, aad, &iv)
}

pub fn decrypt_gcm(payload: &GcmPayload, raw_key: &[u8], aad: &str) -> Result<String, AppError> {
    let iv = decode_base64_url(&payload.iv).map_err(|_| AppError::BadEncryptedPayloadFormat)?;
    let ciphertext =
        decode_base64_url(&payload.ciphertext).map_err(|_| AppError::BadEncryptedPayloadFormat)?;
    let tag = decode_base64_url(&payload.tag).map_err(|_| AppError::BadEncryptedPayloadFormat)?;
    if iv.len() != 12 || ciphertext.is_empty() || tag.len() != 16 {
        return Err(AppError::BadEncryptedPayloadFormat);
    }

    let combined = [&ciphertext[..], &tag[..]].concat();
    let decrypted = decrypt_gcm_combined(&combined, raw_key, aad, &iv)?;
    String::from_utf8(decrypted).map_err(|_| AppError::RequestJsonInvalid)
}

pub fn signature_canonical(input: &SignatureInput<'_>) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}",
        input.method.to_uppercase(),
        input.route,
        input.timestamp,
        input.nonce,
        sha256_hex_bytes(input.body)
    )
}

pub fn request_signature(secret: &[u8], input: &SignatureInput<'_>) -> Result<String, AppError> {
    hmac_sha256_hex(secret, signature_canonical(input).as_bytes())
}

pub fn decrypt_client_session_key(
    wrapped_key: &[u8],
    private_key_pem: &str,
    algorithm: ClientCryptoAlgorithm,
) -> Result<Vec<u8>, AppError> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|_| AppError::CryptoError("客户端私钥不可用"))?;
    let session_key = match algorithm {
        ClientCryptoAlgorithm::RsaOaepAes256Gcm | ClientCryptoAlgorithm::RsaOaepAes128Gcm => {
            private_key.decrypt(Oaep::new::<Sha1>(), wrapped_key)
        }
        ClientCryptoAlgorithm::RsaPkcs1Aes256Gcm => {
            private_key.decrypt(Pkcs1v15Encrypt, wrapped_key)
        }
    }
    .map_err(|_| AppError::BadEncryptedSessionKeyDecryptFailed)?;
    if session_key.len() != algorithm.key_bytes() {
        return Err(AppError::BadEncryptedSessionKeyLength);
    }
    Ok(session_key)
}

pub fn verify_p256_signature(
    public_key_pem: &str,
    canonical: &str,
    signature: &str,
) -> Result<(), AppError> {
    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|_| AppError::DevicePublicKeyInvalid("设备公钥格式错误"))?;
    let signature_bytes = decode_base64_url(signature)
        .map_err(|_| AppError::BadDeviceSignature("设备签名格式错误"))?;
    if signature_bytes.is_empty() {
        return Err(AppError::BadDeviceSignature("设备签名格式错误"));
    }
    let signature = P256Signature::from_der(&signature_bytes)
        .map_err(|_| AppError::BadDeviceSignature("设备签名错误"))?;
    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| AppError::BadDeviceSignature("设备签名错误"))
}

pub fn normalize_p256_public_key(public_key_pem: &str) -> Result<String, AppError> {
    let public_key = public_key_pem.trim();
    if public_key.is_empty() || public_key.len() > 4096 {
        return Err(AppError::DevicePublicKeyInvalid("设备公钥格式错误"));
    }
    let der = pem_public_key_der(public_key)?;
    assert_p256_subject_public_key_info(&der)?;
    Ok(public_key_pem_from_der(&der))
}

pub fn p256_public_key_fingerprint(public_key_pem: &str) -> Result<String, AppError> {
    Ok(sha256_hex(&normalize_p256_public_key(public_key_pem)?))
}

fn pem_public_key_der(public_key: &str) -> Result<Vec<u8>, AppError> {
    let mut in_public_key = false;
    let mut base64_body = String::new();
    for line in public_key.lines().map(str::trim) {
        match line {
            "-----BEGIN PUBLIC KEY-----" => in_public_key = true,
            "-----END PUBLIC KEY-----" => break,
            _ if in_public_key => base64_body.push_str(line),
            _ => {}
        }
    }
    if base64_body.is_empty() {
        return Err(AppError::DevicePublicKeyInvalid("设备公钥格式错误"));
    }
    STANDARD
        .decode(base64_body)
        .map_err(|_| AppError::DevicePublicKeyInvalid("设备公钥格式错误"))
}

fn assert_p256_subject_public_key_info(der: &[u8]) -> Result<(), AppError> {
    let mut outer = DerReader::new(der);
    let subject_public_key_info = outer.read_tlv(0x30)?;
    outer.assert_finished()?;

    let mut reader = DerReader::new(subject_public_key_info);
    let algorithm = reader.read_tlv(0x30)?;
    let public_key = reader.read_tlv(0x03)?;
    reader.assert_finished()?;

    let mut algorithm_reader = DerReader::new(algorithm);
    if algorithm_reader.read_tlv(0x06)? != EC_PUBLIC_KEY_OID {
        return Err(AppError::DevicePublicKeyInvalid(
            "设备公钥必须是 P-256 ECDSA 公钥",
        ));
    }
    if algorithm_reader.read_tlv(0x06)? != PRIME256V1_OID {
        return Err(AppError::DevicePublicKeyInvalid(
            "设备公钥必须是 P-256 ECDSA 公钥",
        ));
    }
    algorithm_reader.assert_finished()?;

    if public_key.len() != 66 || public_key[0] != 0 || public_key[1] != 0x04 {
        return Err(AppError::DevicePublicKeyInvalid("设备公钥格式错误"));
    }
    Ok(())
}

fn public_key_pem_from_der(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is utf-8"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

struct DerReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], AppError> {
        if self.offset >= self.bytes.len() || self.bytes[self.offset] != expected_tag {
            return Err(AppError::DevicePublicKeyInvalid("设备公钥格式错误"));
        }
        self.offset += 1;
        let length = self.read_length()?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AppError::DevicePublicKeyInvalid("设备公钥格式错误"))?;
        if end > self.bytes.len() {
            return Err(AppError::DevicePublicKeyInvalid("设备公钥格式错误"));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn assert_finished(&self) -> Result<(), AppError> {
        if self.offset == self.bytes.len() {
            return Ok(());
        }
        Err(AppError::DevicePublicKeyInvalid("设备公钥格式错误"))
    }

    fn read_length(&mut self) -> Result<usize, AppError> {
        if self.offset >= self.bytes.len() {
            return Err(AppError::DevicePublicKeyInvalid("设备公钥格式错误"));
        }
        let first = self.bytes[self.offset];
        self.offset += 1;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let byte_count = (first & 0x7F) as usize;
        if byte_count == 0 || byte_count > 4 || self.offset + byte_count > self.bytes.len() {
            return Err(AppError::DevicePublicKeyInvalid("设备公钥格式错误"));
        }
        let mut length = 0_usize;
        for _ in 0..byte_count {
            length = (length << 8) | self.bytes[self.offset] as usize;
            self.offset += 1;
        }
        Ok(length)
    }
}

pub fn hmac_sha256_hex_string(secret: &[u8], value: &str) -> Result<String, AppError> {
    hmac_sha256_hex(secret, value.as_bytes())
}

pub(crate) fn hmac_sha256_bytes(secret: &[u8], chunks: &[&[u8]]) -> Result<Vec<u8>, AppError> {
    hmac_sha256_raw(secret, chunks)
}

pub fn generate_client_rsa_key_pair(system_key: &str) -> Result<ClientKeyPair, AppError> {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
        .map_err(|_| AppError::CryptoError("客户端密钥对生成失败"))?;
    let public_key = RsaPublicKey::from(&private_key)
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| AppError::CryptoError("请求加密公钥导出失败"))?;
    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| AppError::CryptoError("客户端私钥导出失败"))?;
    Ok(ClientKeyPair {
        public_key,
        private_key_cipher: encrypt_protected_text(private_key_pem.as_str(), system_key)?,
    })
}

pub(crate) fn encrypt_protected_text_with_iv(
    plaintext: &str,
    system_key: &str,
    iv: &[u8; 16],
) -> Result<String, AppError> {
    let key = protected_key(system_key);
    let ciphertext = Aes256CbcEncryptor::new_from_slices(&key, iv)
        .map_err(|_| AppError::CryptoError("受保护文本加密参数错误"))?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
    let mac = hmac_sha256_raw(&key, &[iv, &ciphertext])?;
    let raw = [iv.as_slice(), mac.as_slice(), ciphertext.as_slice()].concat();
    Ok(encode_base64_url(&raw))
}

pub(crate) fn encrypt_gcm_with_iv(
    plaintext: &str,
    raw_key: &[u8],
    aad: &str,
    iv: &[u8; 12],
) -> Result<GcmPayload, AppError> {
    let combined = encrypt_gcm_combined(plaintext.as_bytes(), raw_key, aad, iv)?;
    let tag_offset = combined
        .len()
        .checked_sub(16)
        .ok_or(AppError::CryptoError("AES-GCM 加密失败"))?;
    Ok(GcmPayload {
        iv: encode_base64_url(iv),
        ciphertext: encode_base64_url(&combined[..tag_offset]),
        tag: encode_base64_url(&combined[tag_offset..]),
    })
}

fn protected_key(system_key: &str) -> [u8; 32] {
    let digest = Sha256::digest(system_key.as_bytes());
    let mut key = [0_u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn assert_protected_text_mac(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    mac: &[u8],
) -> Result<(), AppError> {
    let expected_mac = hmac_sha256_raw(key, &[iv, ciphertext])?;
    if expected_mac.ct_eq(mac).unwrap_u8() != 1 {
        return Err(AppError::CryptoError("受保护文本密钥校验失败"));
    }
    Ok(())
}

fn decrypt_cbc_text(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<String, AppError> {
    let plaintext = Aes256CbcDecryptor::new_from_slices(key, iv)
        .map_err(|_| AppError::CryptoError("受保护文本解密参数错误"))?
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| AppError::CryptoError("受保护文本解密失败"))?;
    String::from_utf8(plaintext).map_err(|_| AppError::CryptoError("受保护文本不是 UTF-8"))
}

fn hmac_sha256_hex(secret: &[u8], value: &[u8]) -> Result<String, AppError> {
    Ok(hex::encode(hmac_sha256_raw(secret, &[value])?))
}

fn hmac_sha256_raw(secret: &[u8], chunks: &[&[u8]]) -> Result<Vec<u8>, AppError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
        .map_err(|_| AppError::CryptoError("HMAC 密钥格式错误"))?;
    for chunk in chunks {
        mac.update(chunk);
    }
    Ok(mac.finalize().into_bytes().to_vec())
}

fn encrypt_gcm_combined(
    plaintext: &[u8],
    raw_key: &[u8],
    aad: &str,
    iv: &[u8],
) -> Result<Vec<u8>, AppError> {
    match raw_key.len() {
        16 => Aes128Gcm::new_from_slice(raw_key)
            .map_err(|_| AppError::CryptoError("AES-GCM 密钥格式错误"))?
            .encrypt(Nonce::from_slice(iv), gcm_payload(plaintext, aad))
            .map_err(|_| AppError::CryptoError("AES-GCM 加密失败")),
        32 => Aes256Gcm::new_from_slice(raw_key)
            .map_err(|_| AppError::CryptoError("AES-GCM 密钥格式错误"))?
            .encrypt(Nonce::from_slice(iv), gcm_payload(plaintext, aad))
            .map_err(|_| AppError::CryptoError("AES-GCM 加密失败")),
        _ => Err(AppError::CryptoError("AES-GCM 密钥长度错误")),
    }
}

fn decrypt_gcm_combined(
    combined: &[u8],
    raw_key: &[u8],
    aad: &str,
    iv: &[u8],
) -> Result<Vec<u8>, AppError> {
    match raw_key.len() {
        16 => Aes128Gcm::new_from_slice(raw_key)
            .map_err(|_| AppError::CryptoError("AES-GCM 密钥格式错误"))?
            .decrypt(Nonce::from_slice(iv), gcm_payload(combined, aad))
            .map_err(|_| AppError::BadEncryptedPayloadVerificationFailed),
        32 => Aes256Gcm::new_from_slice(raw_key)
            .map_err(|_| AppError::CryptoError("AES-GCM 密钥格式错误"))?
            .decrypt(Nonce::from_slice(iv), gcm_payload(combined, aad))
            .map_err(|_| AppError::BadEncryptedPayloadVerificationFailed),
        _ => Err(AppError::CryptoError("AES-GCM 密钥长度错误")),
    }
}

fn gcm_payload<'a>(message: &'a [u8], aad: &'a str) -> Payload<'a, 'a> {
    Payload {
        msg: message,
        aad: aad.as_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{SigningKey, signature::Signer},
        pkcs8::EncodePublicKey,
    };

    #[test]
    fn protected_text_matches_php_compatible_vector() {
        let iv = fixed_iv_16();
        let plaintext = "admin\t0123456789abcdef0123456789abcdef";
        let encrypted = encrypt_protected_text_with_iv(plaintext, "system-key", &iv)
            .expect("protected text should encrypt");

        assert_eq!(
            "AAECAwQFBgcICQoLDA0OD2pySNzBz7rYqp_uXfffoJ7pPRFig5OvUBoEuzdOmATkEoibMc319zTKzpdkFRvwMsGR8Bs6w5ViIXupol7XgRv0mEpnb2DcrZ4LkqX4tp8v",
            encrypted
        );
        assert_eq!(
            plaintext,
            decrypt_protected_text(&encrypted, "system-key")
                .expect("protected text should decrypt")
        );
    }

    #[test]
    fn protected_text_rejects_tampered_mac() {
        let mut encrypted =
            encrypt_protected_text_with_iv("admin\tsession", "system-key", &fixed_iv_16())
                .expect("protected text should encrypt");
        encrypted.replace_range(22..23, "A");

        assert!(decrypt_protected_text(&encrypted, "system-key").is_err());
    }

    #[test]
    fn verifies_p256_der_signature_like_php_client_proof() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key
            .to_public_key_pem(LineEnding::LF)
            .expect("public key pem");
        let canonical = "POST\n/unbind\ninstall_12345678\n1781200300\ncard-hash";
        let signature: P256Signature = signing_key.sign(canonical.as_bytes());
        let encoded_signature = encode_base64_url(signature.to_der().as_bytes());

        verify_p256_signature(&public_key, canonical, &encoded_signature)
            .expect("valid p256 signature");
        assert!(matches!(
            verify_p256_signature(&public_key, "tampered", &encoded_signature),
            Err(AppError::BadDeviceSignature("设备签名错误"))
        ));
    }

    #[test]
    fn gcm_matches_browser_compatible_vector() {
        let key = fixed_key_32();
        let iv = fixed_iv_12();
        let aad = "POST\n/admin/profile/get\n1700000000\nnonce-token";
        let encrypted = encrypt_gcm_with_iv("{\"hello\":\"world\"}", &key, aad, &iv)
            .expect("gcm should encrypt");

        assert_eq!(
            GcmPayload {
                iv: "AAECAwQFBgcICQoL".to_string(),
                ciphertext: "PCC-fqmJrTm3Y-Dkw4UcT_4".to_string(),
                tag: "4-dINykD4BbA4KD-xSP2aQ".to_string(),
            },
            encrypted
        );
        assert_eq!(
            "{\"hello\":\"world\"}",
            decrypt_gcm(&encrypted, &key, aad).expect("gcm should decrypt")
        );
    }

    #[test]
    fn rejects_empty_gcm_payload_shape_like_php() {
        let encrypted = GcmPayload {
            iv: String::new(),
            ciphertext: String::new(),
            tag: String::new(),
        };

        assert!(matches!(
            decrypt_gcm(&encrypted, &fixed_key_32(), ""),
            Err(AppError::BadEncryptedPayloadFormat)
        ));
    }

    #[test]
    fn rejects_invalid_gcm_base64url_like_php_payload_shape() {
        let encrypted = GcmPayload {
            iv: "*".to_string(),
            ciphertext: "*".to_string(),
            tag: "*".to_string(),
        };

        assert!(matches!(
            decrypt_gcm(&encrypted, &fixed_key_32(), ""),
            Err(AppError::BadEncryptedPayloadFormat)
        ));
    }

    #[test]
    fn request_signature_matches_frontend_canonical_format() {
        let key = fixed_key_32();
        let input = SignatureInput {
            method: "POST",
            route: "/admin/profile/get",
            timestamp: "1700000000",
            nonce: "nonce-token",
            body: b"{}",
        };

        assert_eq!(
            "POST\n/admin/profile/get\n1700000000\nnonce-token\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            signature_canonical(&input)
        );
        assert_eq!(
            "8b761c1f3189aa864c911872c331c533b64f4001914481c0d1c54f73a2419aed",
            request_signature(&key, &input).expect("signature should be generated")
        );
    }

    fn fixed_iv_16() -> [u8; 16] {
        let mut iv = [0_u8; 16];
        for (index, value) in iv.iter_mut().enumerate() {
            *value = index as u8;
        }
        iv
    }

    fn fixed_iv_12() -> [u8; 12] {
        let mut iv = [0_u8; 12];
        for (index, value) in iv.iter_mut().enumerate() {
            *value = index as u8;
        }
        iv
    }

    fn fixed_key_32() -> [u8; 32] {
        let mut key = [0_u8; 32];
        for (index, value) in key.iter_mut().enumerate() {
            *value = index as u8;
        }
        key
    }
}
