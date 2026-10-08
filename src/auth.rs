//! Legacy RFB authentication. These algorithms provide compatibility, NOT
//! transport security. Callers must establish SSH/TLS or explicitly opt out.
use aes::cipher::{BlockEncrypt, KeyInit};
use anyhow::{Result, ensure};
use md5::{Digest, Md5};
use num_bigint::BigUint;
use zeroize::{Zeroize, Zeroizing};

pub fn random_bytes(bytes: &mut [u8]) -> Result<()> {
    getrandom::getrandom(bytes).map_err(|e| anyhow::anyhow!("OS random source failed: {e}"))
}

/// Classic VNC authentication uses an eight-byte, bit-reversed DES key.
/// Reject longer/non-ASCII passwords instead of silently truncating them.
pub fn vnc_response(password: &[u8], challenge: [u8; 16]) -> Result<[u8; 16]> {
    ensure!(password.len() <= 8 && password.is_ascii(),
        "classic VNC requires an ASCII password of at most 8 bytes; use ARD for a Mac account password");
    let mut key = Zeroizing::new([0u8; 8]);
    for (dst, src) in key.iter_mut().zip(password) { *dst = src.reverse_bits(); }
    let cipher = des::Des::new_from_slice(key.as_ref())?;
    let mut result = challenge;
    for chunk in result.chunks_exact_mut(8) {
        cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(chunk));
    }
    Ok(result)
}

fn padded(value: &BigUint, len: usize) -> Result<Vec<u8>> {
    let mut bytes = value.to_bytes_be();
    ensure!(bytes.len() <= len, "DH value exceeds negotiated size");
    let mut out = vec![0; len];
    out[len - bytes.len()..].copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}

/// ARD security type 30: DH, MD5(shared secret), AES-128-ECB(credentials).
/// The server supplies a legacy group; even a valid response does not
/// authenticate that server. Require an authenticated outer transport.
pub fn ard_response(generator: u16, modulus: &[u8], peer: &[u8],
                    username: &str, password: &str) -> Result<Vec<u8>> {
    ensure!((64..=512).contains(&modulus.len()) && peer.len() == modulus.len(),
        "invalid ARD DH key length (expected 64..512 bytes)");
    ensure!(!username.is_empty() && username.len() < 64 && password.len() < 64,
        "ARD username/password must each fit in 63 UTF-8 bytes");
    ensure!(!username.contains('\0') && !password.contains('\0'), "NUL in ARD credential");
    let p = BigUint::from_bytes_be(modulus);
    let y = BigUint::from_bytes_be(peer);
    let g = BigUint::from(generator);
    let two = BigUint::from(2u8);
    ensure!(p.bits() >= 512 && (&p & BigUint::from(1u8)) == BigUint::from(1u8),
        "invalid ARD DH modulus");
    let upper = &p - &two;
    ensure!(g >= two && g <= upper && y >= two && y <= upper, "invalid ARD DH public value");
    let mut entropy = Zeroizing::new(vec![0; modulus.len()]);
    random_bytes(&mut entropy)?;
    let private = BigUint::from_bytes_be(&entropy) % (&p - BigUint::from(3u8)) + &two;
    let public = g.modpow(&private, &p);
    let shared = y.modpow(&private, &p);
    ensure!(shared > BigUint::from(1u8), "degenerate ARD shared secret");
    let secret = Zeroizing::new(padded(&shared, modulus.len())?);
    let mut key = Md5::digest(secret.as_slice());
    let cipher = aes::Aes128::new_from_slice(&key)?;
    key.as_mut_slice().zeroize();
    let mut credentials = Zeroizing::new([0u8; 128]);
    random_bytes(credentials.as_mut())?;
    credentials[..username.len()].copy_from_slice(username.as_bytes());
    credentials[username.len()] = 0;
    credentials[64..64 + password.len()].copy_from_slice(password.as_bytes());
    credentials[64 + password.len()] = 0;
    for block in credentials.chunks_exact_mut(16) {
        cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(block));
    }
    let mut response = credentials.to_vec();
    response.extend(padded(&public, modulus.len())?);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockDecrypt;

    #[test]
    fn classic_vnc_known_des_vector() {
        let password: Vec<u8> = [0x13u8, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]
            .iter().map(|v| v.reverse_bits()).collect();
        // DES known vector is tested directly; credential policy is tested separately.
        let key: Vec<u8> = password.iter().map(|v| v.reverse_bits()).collect();
        let cipher = des::Des::new_from_slice(&key).unwrap();
        let mut block = [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef];
        cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(&mut block));
        assert_eq!(block, [0x85,0xe8,0x13,0x54,0x0f,0x0a,0xb4,0x05]);
    }

    #[test]
    fn rejects_credential_truncation() {
        assert!(vnc_response(b"123456789", [0; 16]).is_err());
        assert!(vnc_response("密碼".as_bytes(), [0;16]).is_err());
        assert!(vnc_response(b"password", [0;16]).is_ok());
    }

    #[test]
    fn ard_response_decrypts_with_server_shared_secret() {
        // RFC 2409 group 1, used only as a protocol interoperability fixture.
        let hex = concat!("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
          "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
          "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
          "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF");
        let p = BigUint::parse_bytes(hex.as_bytes(), 16).unwrap();
        let size = p.to_bytes_be().len();
        let server_private = BigUint::from(1234567u32);
        let server_public = BigUint::from(2u8).modpow(&server_private, &p);
        let response = ard_response(2, &padded(&p, size).unwrap(),
            &padded(&server_public,size).unwrap(), "albert", "密碼-password").unwrap();
        let client_public = BigUint::from_bytes_be(&response[128..]);
        let shared = client_public.modpow(&server_private, &p);
        let key = Md5::digest(padded(&shared,size).unwrap());
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();
        let mut plain = response[..128].to_vec();
        for b in plain.chunks_exact_mut(16) {
            cipher.decrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(b));
        }
        assert_eq!(&plain[..7], b"albert\0");
        assert!(plain[64..].starts_with("密碼-password\0".as_bytes()));
    }

    #[test]
    fn rejects_bad_ard_parameters() {
        assert!(ard_response(0, &[0;64], &[0;64], "a", "b").is_err());
        assert!(ard_response(2, &[255;513], &[2;513], "a", "b").is_err());
        assert!(ard_response(2, &[255;64], &[2;64], &"u".repeat(64), "b").is_err());
    }
}
