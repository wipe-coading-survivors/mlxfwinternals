//! Чистая логика dump-лесенки: разбор дельт и имена файлов. IO (снап/дамп) — в main.rs.

/// Разбор "0,1,2,5,10" -> [0,1,2,5,10]. Ошибка: пустая строка, пустой токен, не-целое.
pub fn parse_deltas(s: &str) -> anyhow::Result<Vec<u64>> {
    let mut out = Vec::new();
    for p in s.split(',') {
        let t = p.trim();
        if t.is_empty() {
            anyhow::bail!("empty delta in {s:?}");
        }
        out.push(t.parse::<u64>()?);
    }
    if out.is_empty() {
        anyhow::bail!("no deltas in {s:?}");
    }
    Ok(out)
}

/// 0->"t00", 1->"t01", 5->"t05", 10->"t10".
pub fn dump_suffix(delta: u64) -> String {
    format!("t{:02}", delta)
}

/// "<BASE>-t<NN>.raw".
pub fn dump_path(base: &str, delta: u64) -> String {
    format!("{}-{}.raw", base, dump_suffix(delta))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_deltas_ladder() {
        assert_eq!(parse_deltas("0,1,2,5,10").unwrap(), vec![0u64, 1, 2, 5, 10]);
    }

    #[test]
    fn parse_deltas_single() {
        assert_eq!(parse_deltas("3").unwrap(), vec![3u64]);
    }

    #[test]
    fn parse_deltas_rejects_empty_and_bad() {
        assert!(parse_deltas("").is_err());
        assert!(parse_deltas("0,,1").is_err());
        assert!(parse_deltas("1,x").is_err());
    }

    #[test]
    fn dump_suffix_pads_two_digits() {
        assert_eq!(dump_suffix(0), "t00");
        assert_eq!(dump_suffix(1), "t01");
        assert_eq!(dump_suffix(5), "t05");
        assert_eq!(dump_suffix(10), "t10");
    }

    #[test]
    fn dump_path_shape() {
        assert_eq!(
            dump_path("/tmp/s3trig-202610051430", 10),
            "/tmp/s3trig-202610051430-t10.raw"
        );
    }
}
