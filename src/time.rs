//! RFC 3339 without a date crate: rustic writes
//! `2026-09-23T04:40:35.297023632+02:00`, and all we need is "how many
//! hours ago".

use std::time::{SystemTime, UNIX_EPOCH};

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn num(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)` → seconds since the Unix epoch.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let (date, rest) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, day) = (
        num(d.next()?)?,
        num(d.next()?)? as u32,
        num(d.next()?)? as u32,
    );
    if d.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    let (time, offset_sign, offset) = if let Some(t) = rest.strip_suffix('Z') {
        (t, 1, "00:00")
    } else if let Some((t, o)) = rest.rsplit_once('+') {
        (t, 1, o)
    } else if let Some((t, o)) = rest.rsplit_once('-') {
        (t, -1, o)
    } else {
        return None;
    };
    let time = time.split_once('.').map_or(time, |(t, _)| t);
    let mut t = time.split(':');
    let (hh, mm, ss) = (num(t.next()?)?, num(t.next()?)?, num(t.next()?)?);
    if t.next().is_some() || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let (oh, om) = offset.split_once(':')?;
    let off = (num(oh)? * 3600 + num(om)? * 60) * offset_sign;
    Some(days_from_civil(y, m, day) * 86_400 + hh * 3600 + mm * 60 + ss - off)
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn hours_between(earlier: i64, later: i64) -> u64 {
    ((later - earlier).max(0) / 3600) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rustic_timestamp_with_nanos_and_offset() {
        // 2026-09-23T04:40:35+02:00 == 2026-09-23T02:40:35Z
        let t = parse_rfc3339("2026-09-23T04:40:35.297023632+02:00").unwrap();
        assert_eq!(t, parse_rfc3339("2026-09-23T02:40:35Z").unwrap());
    }

    #[test]
    fn unix_epoch_and_a_known_date() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(parse_rfc3339("2026-09-23T02:40:35Z"), Some(1_790_131_235));
    }

    #[test]
    fn garbage_is_none() {
        assert_eq!(parse_rfc3339("gestern"), None);
        assert_eq!(parse_rfc3339("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-09-23 02:40:35"), None);
    }

    #[test]
    fn hours_between_rounds_down_and_never_goes_negative() {
        assert_eq!(hours_between(0, 3600 * 47 + 3599), 47);
        assert_eq!(hours_between(100, 0), 0);
        assert!(now() > 1_700_000_000);
    }
}
