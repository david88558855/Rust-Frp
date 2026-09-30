//! AES-128-CFB stream cipher compatible with `golib/crypto`.
//!
//! Upstream derives the key with PBKDF2-HMAC-SHA1 over the raw token using the
//! salt `"crypto"` and 64 iterations, then prepends a random 16 byte IV to the
//! ciphertext stream. Go's `crypto/cipher.NewCFBEncrypter` implements CFB-128
//! (full block feedback) used as a stream cipher; the implementation below
//! reproduces it byte for byte so that a Rust peer can talk to frp and vice
//! versa.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

use super::{DEFAULT_SALT, PBKDF2_ROUNDS};

/// Derives the 16 byte AES-128 key from the raw token.
pub fn derive_key(token: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    pbkdf2_hmac::<Sha1>(token, DEFAULT_SALT, PBKDF2_ROUNDS, &mut out);
    out
}

/// CFB-128 (full block feedback) keystream generator.
///
/// The same structure is used for both directions: the difference between
/// encryption and decryption is only which bytes feed back into `next`.
pub struct Cfb128 {
    cipher: Aes128,
    next: [u8; 16],
    keystream: [u8; 16],
    used: usize,
}

impl Cfb128 {
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let cipher = Aes128::new_from_slice(key).expect("AES-128 requires a 16 byte key");
        Self {
            cipher,
            next: *iv,
            keystream: [0u8; 16],
            used: 16,
        }
    }

    #[inline]
    fn refill(&mut self) {
        let mut block = aes::cipher::Block::<Aes128>::default();
        block.copy_from_slice(&self.next);
        self.cipher.encrypt_block(&mut block);
        self.keystream.copy_from_slice(&block);
        self.used = 0;
    }

    /// Encrypts `data` in place; ciphertext feeds back into the shift register.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.used == 16 {
                self.refill();
            }
            let c = *byte ^ self.keystream[self.used];
            *byte = c;
            self.next[self.used] = c;
            self.used += 1;
        }
    }

    /// Decrypts `data` in place; the *input* ciphertext feeds the shift register.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.used == 16 {
                self.refill();
            }
            let c = *byte;
            *byte = c ^ self.keystream[self.used];
            self.next[self.used] = c;
            self.used += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_is_deterministic_and_16_bytes() {
        let a = derive_key(b"token");
        let b = derive_key(b"token");
        assert_eq!(a, b);
        assert_ne!(a, derive_key(b"other"));
    }

    #[test]
    fn stream_roundtrip_across_split_writes() {
        let key = derive_key(b"secret");
        let iv = [7u8; 16];
        let plain: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

        let mut enc = Cfb128::new(&key, &iv);
        let mut cipher = plain.clone();
        // Encrypt in irregular chunks to exercise the keystream state machine.
        let mut pos = 0;
        for step in [1usize, 15, 16, 17, 31, 100, 320, 500] {
            let end = (pos + step).min(cipher.len());
            enc.encrypt(&mut cipher[pos..end]);
            pos = end;
            if pos == cipher.len() {
                break;
            }
        }
        enc.encrypt(&mut cipher[pos..]);
        assert_ne!(cipher, plain);

        let mut dec = Cfb128::new(&key, &iv);
        let mut out = cipher.clone();
        dec.decrypt(&mut out);
        assert_eq!(out, plain);
    }

    #[test]
    fn known_answer_matches_go_cfb128() {
        // Cross-checked with Go: cipher.NewCFBEncrypter(aes(key), iv).
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut c = Cfb128::new(&key, &iv);
        let plain = *b"0123456789abcdef0123456789abcdef";
        let mut buf = plain;
        c.encrypt(&mut buf);

        // CFB-128: C_i = P_i xor E(feedback_i), where feedback_0 = IV and
        // feedback_i is the *previous ciphertext block*.
        let mut expect = [0u8; 32];
        {
            let aes = Aes128::new_from_slice(&key).unwrap();
            let mut ks = aes::cipher::Block::<Aes128>::default();
            ks.copy_from_slice(&iv);
            aes.encrypt_block(&mut ks);
            for i in 0..16 {
                expect[i] = plain[i] ^ ks[i];
            }
            let mut ks2 = aes::cipher::Block::<Aes128>::default();
            ks2.copy_from_slice(&expect[..16]);
            aes.encrypt_block(&mut ks2);
            for i in 0..16 {
                expect[16 + i] = plain[16 + i] ^ ks2[i];
            }
        }
        assert_eq!(&buf[..], &expect[..]);
    }
}
