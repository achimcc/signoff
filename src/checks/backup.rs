//! Is the guest's dataset in the backup repository, and recently? A new
//! guest is in the derived source list at once — its data are in the
//! repository only after the next run.

use crate::config::{Config, Service};
use crate::runner::{Limits, Output, Runner};
use crate::time::{hours_between, parse_rfc3339};
use crate::verdict::Verdict;
use serde_json::Value;

pub const RUSTIC: &str = "rustic";

pub fn args(profile: &str, label: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = vec![
        "-P".into(),
        profile.into(),
        "snapshots".into(),
        "--json".into(),
    ];
    if let Some(l) = label {
        v.push("--filter-label".into());
        v.push(l.into());
    }
    v
}

fn snapshots(out: &Output) -> Result<Vec<Value>, String> {
    if out.code != Some(0) {
        return Err(format!(
            "rustic exit {:?}: {}",
            out.code,
            out.stderr.trim().lines().next().unwrap_or("")
        ));
    }
    let groups: Vec<Value> =
        serde_json::from_str(&out.stdout).map_err(|e| format!("rustic: not JSON: {e}"))?;
    Ok(groups
        .iter()
        .filter_map(|g| g["snapshots"].as_array())
        .flatten()
        .cloned()
        .collect())
}

pub fn judge(out: &Output, dataset: &str, max_age_hours: u64, now: i64) -> Verdict {
    let snaps = match snapshots(out) {
        Ok(s) => s,
        Err(e) => return Verdict::CannotMeasure(e),
    };
    if snaps.is_empty() {
        return Verdict::Failed(format!(
            "no snapshot for {dataset} — start sicherung-offsite.service by hand"
        ));
    }
    let mut newest: Option<(i64, String)> = None;
    for s in &snaps {
        let text = s["time"].as_str().unwrap_or("");
        let Some(t) = parse_rfc3339(text) else {
            return Verdict::CannotMeasure(format!("snapshot time {text:?} is not RFC 3339"));
        };
        if newest.as_ref().is_none_or(|(n, _)| t > *n) {
            newest = Some((t, text.to_string()));
        }
    }
    let (t, text) = newest.expect("non-empty");
    let age = hours_between(t, now);
    if age > max_age_hours {
        Verdict::Failed(format!(
            "newest snapshot is {age} h old (max {max_age_hours}): sicherung-offsite.service did not run?"
        ))
    } else {
        Verdict::Ok(format!(
            "newest {text}, {age} h old ({} snapshots)",
            snaps.len()
        ))
    }
}

pub fn check(r: &dyn Runner, cfg: &Config, s: &Service, now: i64) -> Verdict {
    match r.run_with(
        RUSTIC,
        &args(&cfg.rustic_profile, Some(&s.dataset)),
        None,
        Limits::RUSTIC,
    ) {
        Ok(out) => judge(&out, &s.dataset, cfg.snapshot_max_age_hours, now),
        Err(e) => Verdict::CannotMeasure(e),
    }
}

/// The repository lists something at all — else "no snapshot for X" would
/// be a statement about the repository, not the dataset.
pub fn control_repo(r: &dyn Runner, cfg: &Config) -> Result<(), String> {
    let out = r.run_with(
        RUSTIC,
        &args(&cfg.rustic_profile, None),
        None,
        Limits::RUSTIC,
    )?;
    let snaps = snapshots(&out).map_err(|e| format!("control: {e}"))?;
    if snaps.is_empty() {
        Err(format!(
            "control: {} lists no snapshots at all",
            cfg.rustic_profile
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;
    use crate::runner::{Fake, Output};
    use crate::time::parse_rfc3339;

    const FIN: &str = include_str!("../../tests/answers/rustic-fin-01.json");

    fn out(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }
    fn cfg() -> Config {
        parse(include_str!("../../tests/answers/signoff.toml")).unwrap()
    }
    // 2026-09-23T10:00:00+02:00 — five hours after the newest snapshot.
    fn noon() -> i64 {
        parse_rfc3339("2026-09-23T10:00:00+02:00").unwrap()
    }

    #[test]
    fn args_use_the_profile_and_the_label() {
        assert_eq!(
            args("/etc/rustic/rustic", Some("rpool/guests/fin-01")),
            vec![
                "-P",
                "/etc/rustic/rustic",
                "snapshots",
                "--json",
                "--filter-label",
                "rpool/guests/fin-01"
            ]
        );
        assert_eq!(
            args("/etc/rustic/rustic", None),
            vec!["-P", "/etc/rustic/rustic", "snapshots", "--json"]
        );
    }

    #[test]
    fn fresh_snapshot_is_ok_with_time_and_count() {
        let v = judge(&out(0, FIN, ""), "rpool/guests/fin-01", 48, noon());
        assert_eq!(
            v,
            Verdict::Ok("newest 2026-09-23T04:40:35.297023632+02:00, 5 h old (2 snapshots)".into())
        );
    }

    #[test]
    fn stale_snapshot_is_a_finding() {
        let three_days_later = noon() + 3 * 86_400;
        let v = judge(
            &out(0, FIN, ""),
            "rpool/guests/fin-01",
            48,
            three_days_later,
        );
        assert_eq!(
            v,
            Verdict::Failed(
                "newest snapshot is 77 h old (max 48): sicherung-offsite.service did not run?"
                    .into()
            )
        );
    }

    #[test]
    fn no_snapshot_is_a_finding() {
        assert_eq!(
            judge(&out(0, "[]", ""), "rpool/guests/neu-01", 48, noon()),
            Verdict::Failed(
                "no snapshot for rpool/guests/neu-01 — start sicherung-offsite.service by hand"
                    .into()
            )
        );
    }

    #[test]
    fn rustic_error_or_bad_json_is_cannot_measure() {
        assert!(matches!(
            judge(&out(1, "", "rustic: repository locked"), "d", 48, noon()),
            Verdict::CannotMeasure(_)
        ));
        assert!(matches!(
            judge(&out(0, "not json", ""), "d", 48, noon()),
            Verdict::CannotMeasure(_)
        ));
        let bad_time = FIN.replace("2026-09-23T04:40:35.297023632+02:00", "gestern");
        assert!(matches!(
            judge(&out(0, &bad_time, ""), "rpool/guests/fin-01", 48, noon()),
            Verdict::CannotMeasure(_)
        ));
    }

    #[test]
    fn check_filters_by_the_service_dataset_and_control_needs_one_group() {
        let c = cfg();
        let fake = Fake::new()
            .on(
                "rustic",
                "--filter-label rpool/guests/fin-01",
                out(0, FIN, ""),
            )
            .on("rustic", "snapshots --json", out(0, FIN, ""));
        assert!(matches!(
            check(&fake, &c, c.service("ghostfolio").unwrap(), noon()),
            Verdict::Ok(_)
        ));
        assert!(control_repo(&fake, &c).is_ok());
        let empty = Fake::new().on("rustic", "snapshots --json", out(0, "[]", ""));
        assert!(
            control_repo(&empty, &c)
                .unwrap_err()
                .contains("no snapshots at all")
        );
    }
}
