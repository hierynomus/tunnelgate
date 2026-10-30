/// Parses a Go-style duration (`30s`, `1h30m`, `500ms`) into milliseconds.
pub fn parse_millis(s: &str) -> Result<u64, String> {
    let err = || format!("invalid duration {s:?}: use e.g. 30s, 5m or 1h30m");
    if s.is_empty() {
        return Err(err());
    }
    let mut total: u64 = 0;
    let mut rest = s;
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !c.is_ascii_digit()).ok_or_else(err)?;
        if digits == 0 {
            return Err(err());
        }
        let n: u64 = rest[..digits].parse().map_err(|_| err())?;
        rest = &rest[digits..];
        let (unit, len) = if rest.starts_with("ms") {
            (1, 2)
        } else if rest.starts_with('s') {
            (1_000, 1)
        } else if rest.starts_with('m') {
            (60_000, 1)
        } else if rest.starts_with('h') {
            (3_600_000, 1)
        } else {
            return Err(err());
        };
        total = n.checked_mul(unit).and_then(|v| total.checked_add(v)).ok_or_else(err)?;
        rest = &rest[len..];
    }
    Ok(total)
}

/// Parses a duration into whole seconds (Cloudflare's `originRequest` unit), rounding up.
pub fn parse_seconds(s: &str) -> Result<u64, String> {
    parse_millis(s).map(|ms| ms.div_ceil(1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        assert_eq!(parse_seconds("30s"), Ok(30));
        assert_eq!(parse_seconds("1h30m"), Ok(5400));
        assert_eq!(parse_seconds("1500ms"), Ok(2));
        assert_eq!(parse_millis("8760h"), Ok(8760 * 3_600_000));
        for bad in ["", "s", "10", "10d", "1.5s", "-1s"] {
            assert!(parse_millis(bad).is_err(), "{bad}");
        }
    }
}
