use crate::ess_errors::Result;
use google_authenticator::{ErrorCorrectionLevel, GoogleAuthenticator};
use rand::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

const RFC4648_ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: false };
pub const OTP_DEFAULT_CODE_LEN: usize = 6;
pub const OTP_DEFAULT_EXPIRE_CODE_SEC: u8 = 30;
pub const OTP_DEFAULT_DISCREPANCY: u64 = 1;

pub struct Otpist {
    gauth: GoogleAuthenticator,
    code_expire_sec: u8,
    code_len: usize,
    discrepancy: u64,
}

impl Clone for Otpist {
    fn clone(&self) -> Self {
        Self::new_with(self.code_len, self.code_expire_sec, self.discrepancy)
    }
}

pub fn convert_to_base32(text: &str) -> String {
    if is_base32(text) {
        text.to_string()
    } else {
        to_base32(text)
    }
}

fn to_base32(text: &str) -> String {
    base32::encode(RFC4648_ALPHABET, text.as_bytes())
}

fn is_base32(text: &str) -> bool {
    base32::decode(RFC4648_ALPHABET, text).is_some()
}

impl Otpist {
    pub fn new() -> Self {
        Self::new_with(
            OTP_DEFAULT_CODE_LEN,
            OTP_DEFAULT_EXPIRE_CODE_SEC,
            OTP_DEFAULT_DISCREPANCY,
        )
    }

    pub fn new_with(code_len: usize, code_expire_sec: u8, discrepancy: u64) -> Self {
        Otpist {
            gauth: GoogleAuthenticator::new().with_code_length(code_len),
            code_expire_sec: code_expire_sec,
            code_len: code_len,
            discrepancy: discrepancy,
        }
    }

    pub fn new_secret(&self) -> String {
        let mut randomness = ThreadRng::default();
        let mut arr = Vec::with_capacity(80);

        arr.extend_from_slice(&self.timeslice().to_le_bytes());

        for _ in 0..9 {
            arr.extend_from_slice(&randomness.next_u64().to_le_bytes());
        }

        base32::encode(RFC4648_ALPHABET, &arr)
    }

    fn timeslice(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(200_000))
            .as_secs()
            / self.code_expire_sec as u64
    }

    pub fn code(&self, secret: &str) -> Result<String> {
        let timeslice = self.timeslice();
        let code = if is_base32(secret) {
            self.gauth.get_code(&secret, timeslice)?
        } else {
            let secret_b32 = to_base32(secret);
            self.gauth.get_code(&secret_b32, timeslice)?
        };

        println!("[otp] hmac(t:{}, s:{}) => {}", timeslice, secret, code);
        Ok(code)
    }

    pub fn verify_code(&self, secret: &str, code: &str) -> bool {
        let timeslice = self.timeslice();
        if is_base32(secret) {
            self.gauth
                .verify_code(secret, code, self.discrepancy, timeslice)
        } else {
            let secret_b32 = to_base32(secret);
            self.gauth
                .verify_code(&secret_b32, code, self.discrepancy, timeslice)
        }
    }

    pub fn secret_to_qr_code(&self, username: &str, secret: &str) -> String {
        let welcome = format!("Authenticate as '{}' to ESS", username);
        let secret = convert_to_base32(secret);

        self.gauth
            .qr_code_url(&secret, "ESS", &welcome, 0, 0, ErrorCorrectionLevel::Medium)
    }
}
