use std::io::{self, Write};

pub const REQUIRED: &str = "--operation-key is required; specify a key or 'auto'";

#[derive(Debug, PartialEq)]
pub enum Selection {
    Explicit(String),
    Auto,
}

impl Selection {
    pub fn parse(value: String) -> Result<Self, &'static str> {
        if !(1..=256).contains(&value.len()) {
            return Err("operation key must contain 1–256 UTF-8 bytes");
        }
        Ok(if value == "auto" {
            Self::Auto
        } else {
            Self::Explicit(value)
        })
    }

    pub fn resolve(self) -> Result<Key, &'static str> {
        match self {
            Self::Explicit(value) => Ok(Key {
                value,
                generated: false,
            }),
            Self::Auto => {
                let mut random = [0_u8; 16];
                getrandom::fill(&mut random).map_err(|_| "cannot generate operation key")?;
                let value = random
                    .iter()
                    .flat_map(|b| {
                        const HEX: &[u8; 16] = b"0123456789abcdef";
                        [
                            char::from(HEX[(b >> 4) as usize]),
                            char::from(HEX[(b & 15) as usize]),
                        ]
                    })
                    .collect();
                Ok(Key {
                    value,
                    generated: true,
                })
            }
        }
    }
}

pub struct Key {
    pub value: String,
    generated: bool,
}

impl Key {
    pub fn announce(&self, mut stderr: impl Write) -> io::Result<()> {
        if self.generated {
            writeln!(stderr, "asterctl: operation-key={}", self.value)?;
            stderr.flush()?;
        }
        Ok(())
    }

    pub fn retry_instruction(&self) -> String {
        if self
            .value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._/:".contains(&b))
        {
            return format!(
                "retry the identical request with --operation-key={}",
                self.value
            );
        }
        // Do not turn arbitrary UTF-8 keys into shell commands or terminal controls.
        // ASCII-only JSON retains the exact key, including control characters.
        let json = serde_json::to_string(&self.value).expect("UTF-8 key");
        let mut escaped = String::new();
        for c in json.chars() {
            if c.is_ascii() && !c.is_control() {
                escaped.push(c);
            } else {
                use std::fmt::Write;
                for unit in c.encode_utf16(&mut [0; 2]) {
                    write!(escaped, "\\u{unit:04x}").expect("string write");
                }
            }
        }
        format!(
            "retry the identical request with --operation-key set to the key encoded by this JSON string: {escaped}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_must_reach_the_underlying_writer() {
        let key = Selection::Auto.resolve().unwrap();
        let mut sink = Vec::new();
        let mut writer = io::BufWriter::new(&mut sink);
        key.announce(&mut writer).unwrap();
        assert!(writer.buffer().is_empty());
        drop(writer);
        assert_eq!(
            sink,
            format!("asterctl: operation-key={}\n", key.value).as_bytes()
        );

        struct FlushFailure;
        impl Write for FlushFailure {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        assert_eq!(
            key.announce(FlushFailure).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        // Explicit keys need no announcement, even with unusable stderr.
        Selection::Explicit("saved-key".into())
            .resolve()
            .unwrap()
            .announce(FlushFailure)
            .unwrap();
    }

    #[test]
    fn recovery_preserves_keys_without_terminal_controls_or_shell_interpolation() {
        let original = "читач\n\t\x1b\x7f\u{202e}😀'\"$()`\\";
        let key = Selection::Explicit(original.into()).resolve().unwrap();
        let message = key.retry_instruction();
        assert!(message.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
        let json = message.split_once("JSON string: ").unwrap().1;
        assert_eq!(serde_json::from_str::<String>(json).unwrap(), original);
    }
}
