pub fn topic(value: &str) -> Result<(), &'static str> {
    if !(1..=128).contains(&value.len()) {
        return Err("topic must contain 1–128 ASCII characters");
    }
    if !value.bytes().all(name_char) {
        return Err(
            "invalid topic: use ASCII letters, digits, '.', '_' or '-'; '/' is not allowed",
        );
    }
    Ok(())
}

pub fn scope(value: &str) -> Result<(), &'static str> {
    if !(1..=128).contains(&value.len()) {
        return Err("scope must contain 1–128 ASCII characters");
    }
    if !value.bytes().all(|b| name_char(b) || b == b'/') {
        return Err(
            "invalid scope: use ASCII letters, digits, '.', '_', '-' or '/' between segments",
        );
    }
    if !value
        .split('/')
        .all(|s| !s.is_empty() && s != "." && s != "..")
    {
        return Err(
            "invalid scope: leading or trailing slashes, empty segments, '.' and '..' segments are not allowed",
        );
    }
    Ok(())
}

fn name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

pub fn identity(value: &str) -> Option<Vec<u8>> {
    if value.len() > 44 {
        return None;
    }
    let bytes: Vec<u8> =
        buffa::json_helpers::bytes::deserialize(serde::de::value::StrDeserializer::<
            serde::de::value::Error,
        >::new(value))
        .ok()?;
    (bytes.len() == 32).then_some(bytes)
}
