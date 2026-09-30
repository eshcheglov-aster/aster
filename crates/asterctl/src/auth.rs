use std::{fmt, fs::OpenOptions, io::Read, path::Path};
use zeroize::Zeroizing;

#[derive(PartialEq)]
pub struct Token(Zeroizing<String>);

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token([redacted])")
    }
}

impl Token {
    pub fn parse(value: String) -> Result<Self, &'static str> {
        let value = Zeroizing::new(value);
        if !(32..=256).contains(&value.len())
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err("token must contain 32 to 256 ASCII letters, digits, or -._~");
        }
        Ok(Self(value))
    }

    pub fn load(path: &Path) -> Result<Self, &'static str> {
        const MAX_FILE_BYTES: u64 = 258;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options.open(path).map_err(|_| "cannot open token file")?;
        let metadata = file.metadata().map_err(|_| "cannot inspect token file")?;
        if !metadata.is_file() {
            return Err("token file must be a regular file");
        }
        if metadata.len() > MAX_FILE_BYTES {
            return Err("token file exceeds 258 bytes");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read token file")?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err("token file exceeds 258 bytes");
        }
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        let value = std::str::from_utf8(&bytes).map_err(|_| "token must be ASCII")?;
        Self::parse(value.to_owned())
    }

    pub fn header(&self) -> http::HeaderValue {
        let text = Zeroizing::new(format!("Bearer {}", self.0.as_str()));
        let mut header = http::HeaderValue::from_str(&text).expect("validated ASCII token");
        header.set_sensitive(true);
        header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    const TOKEN: &str = "asterctl-test-token-00000000000000";

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(bytes: &[u8]) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "asterctl-auth-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&path).unwrap().write_all(bytes).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn token_file_accepts_raw_lf_and_crlf() {
        for suffix in ["", "\n", "\r\n"] {
            let file = Fixture::new(format!("{TOKEN}{suffix}").as_bytes());
            assert_eq!(
                Token::load(&file.0).unwrap(),
                Token::parse(TOKEN.to_owned()).unwrap()
            );
        }
    }

    #[test]
    fn token_file_is_bounded_and_requires_valid_token_bytes() {
        for bytes in [
            vec![],
            vec![b'a'; 259],
            vec![b'a'; 257],
            vec![255; 32],
            vec![b' '; 32],
            format!(" {TOKEN}\n").into_bytes(),
        ] {
            let file = Fixture::new(&bytes);
            assert!(Token::load(&file.0).is_err());
        }
        assert!(Token::load(&std::env::temp_dir()).is_err());
        let file = Fixture::new(TOKEN.as_bytes());
        let path = file.0.clone();
        drop(file);
        assert!(Token::load(&path).is_err());
        let file = Fixture::new(format!("{}\r\n", "a".repeat(256)).as_bytes());
        assert!(Token::load(&file.0).is_ok());
    }

    #[test]
    fn plain_token_and_debug_output_do_not_allow_header_injection_or_leakage() {
        for text in [
            "short".to_owned(),
            "a".repeat(257),
            format!("{TOKEN}\n"),
            format!("{TOKEN}:x"),
            "é".repeat(32),
        ] {
            assert!(Token::parse(text).is_err());
        }
        let token = Token::parse(TOKEN.to_owned()).unwrap();
        let header = token.header();
        assert_eq!(header.to_str().unwrap(), format!("Bearer {TOKEN}"));
        assert!(header.is_sensitive());
        assert!(!format!("{token:?} {header:?}").contains(TOKEN));
    }
}
