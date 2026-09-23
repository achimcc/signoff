//! Does the name resolve, from outside, to the VPS? The zone carries a
//! wildcard, so "any record" proves nothing — the answer must BE the VPS.

use crate::config::{Config, Service};
use crate::runner::{Output, Runner};
use crate::verdict::Verdict;

pub const DIG: &str = "dig";

pub fn args(resolver: &str, rrtype: &str, name: &str) -> Vec<String> {
    vec![
        "+short".into(),
        "+time=3".into(),
        "+tries=1".into(),
        rrtype.into(),
        name.into(),
        format!("@{resolver}"),
    ]
}

fn looks_like_address(line: &str) -> bool {
    !line.is_empty()
        && line
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
        && (line.contains(':') || line.chars().filter(|c| *c == '.').count() == 3)
}

pub fn judge(out: &Output, rrtype: &str, expected: &str) -> Verdict {
    if out.code != Some(0) {
        return Verdict::CannotMeasure(format!(
            "dig exit {:?}: {}",
            out.code,
            out.stdout.trim().lines().next().unwrap_or("")
        ));
    }
    let addresses: Vec<&str> = out
        .stdout
        .lines()
        .map(str::trim)
        .filter(|l| looks_like_address(l))
        .collect();
    if addresses.contains(&expected) {
        return Verdict::Ok(expected.into());
    }
    match addresses.first() {
        None => Verdict::Failed(format!("no {rrtype} record")),
        Some(first) => Verdict::Failed(format!(
            "{rrtype} points to {first}, expected {expected} (wildcard or missing record — just dns-apply?)"
        )),
    }
}

fn check(r: &dyn Runner, cfg: &Config, s: &Service, rrtype: &str, expected: &str) -> Verdict {
    if !s.public {
        return Verdict::NotApplicable("not public".into());
    }
    match r.run(DIG, &args(&cfg.resolver, rrtype, &s.host), None) {
        Ok(out) => judge(&out, rrtype, expected),
        Err(e) => Verdict::CannotMeasure(e),
    }
}

pub fn check_a(r: &dyn Runner, cfg: &Config, s: &Service) -> Verdict {
    check(r, cfg, s, "A", &cfg.vps_v4)
}

pub fn check_aaaa(r: &dyn Runner, cfg: &Config, s: &Service) -> Verdict {
    check(r, cfg, s, "AAAA", &cfg.vps_v6)
}

/// The resolver answers for the zone at all — otherwise "no record" would
/// be a statement about the network, not the zone.
pub fn control_soa(r: &dyn Runner, cfg: &Config) -> Result<(), String> {
    let out = r.run(DIG, &args(&cfg.resolver, "SOA", &cfg.zone), None)?;
    if out.code == Some(0) && !out.stdout.trim().is_empty() {
        Ok(())
    } else {
        Err(format!(
            "control: {} did not answer SOA {} (exit {:?})",
            cfg.resolver, cfg.zone, out.code
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;
    use crate::runner::{Fake, Output};

    fn out(stdout: &str, code: i32) -> Output {
        Output {
            code: Some(code),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
    fn cfg() -> Config {
        parse(include_str!("../../tests/answers/signoff.toml")).unwrap()
    }

    #[test]
    fn args_pin_short_timeout_and_resolver() {
        assert_eq!(
            args("1.1.1.1", "AAAA", "x.rusty-vault.de"),
            vec![
                "+short",
                "+time=3",
                "+tries=1",
                "AAAA",
                "x.rusty-vault.de",
                "@1.1.1.1"
            ]
        );
    }

    #[test]
    fn expected_address_is_ok() {
        let v = judge(
            &out(include_str!("../../tests/answers/dig-a-ok.txt"), 0),
            "A",
            "77.42.71.141",
        );
        assert_eq!(v, Verdict::Ok("77.42.71.141".into()));
    }

    #[test]
    fn cloudflare_address_is_a_finding_that_names_it() {
        let v = judge(
            &out(include_str!("../../tests/answers/dig-a-cloudflare.txt"), 0),
            "A",
            "77.42.71.141",
        );
        assert_eq!(
            v,
            Verdict::Failed(
                "A points to 104.21.32.1, expected 77.42.71.141 (wildcard or missing record — just dns-apply?)".into()
            )
        );
    }

    #[test]
    fn dig_a_finds_address_behind_cname() {
        let v = judge(
            &out(include_str!("../../tests/answers/dig-cname-then-a.txt"), 0),
            "A",
            "77.42.71.141",
        );
        assert_eq!(v, Verdict::Ok("77.42.71.141".into()));
    }

    #[test]
    fn empty_answer_is_a_finding_and_resolver_failure_is_cannot_measure() {
        assert_eq!(
            judge(&out("", 0), "AAAA", "2a01::1"),
            Verdict::Failed("no AAAA record".into())
        );
        let v = judge(
            &Output {
                code: Some(9),
                stdout: ";; communications error".into(),
                stderr: String::new(),
            },
            "A",
            "x",
        );
        assert!(matches!(v, Verdict::CannotMeasure(_)));
    }

    #[test]
    fn internal_service_is_not_applicable() {
        let c = cfg();
        let fake = Fake::new();
        assert_eq!(
            check_a(&fake, &c, c.service("radarr").unwrap()),
            Verdict::NotApplicable("not public".into())
        );
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn check_a_and_aaaa_ask_for_the_service_host() {
        let c = cfg();
        let fake = Fake::new()
            .on(
                "dig",
                "AAAA ghostfolio.rusty-vault.de",
                out("2a01:4f9:c013:5ee7::1\n", 0),
            )
            .on(
                "dig",
                "A ghostfolio.rusty-vault.de",
                out("77.42.71.141\n", 0),
            );
        let s = c.service("ghostfolio").unwrap();
        assert_eq!(check_a(&fake, &c, s), Verdict::Ok("77.42.71.141".into()));
        assert_eq!(
            check_aaaa(&fake, &c, s),
            Verdict::Ok("2a01:4f9:c013:5ee7::1".into())
        );
    }

    #[test]
    fn soa_control_needs_a_non_empty_answer() {
        let c = cfg();
        let ok = Fake::new().on(
            "dig",
            "SOA rusty-vault.de",
            out("ns.example. hostmaster. 1 2 3 4 5\n", 0),
        );
        assert!(control_soa(&ok, &c).is_ok());
        let silent = Fake::new().on("dig", "SOA", out("", 9));
        let e = control_soa(&silent, &c).unwrap_err();
        assert!(e.contains("1.1.1.1"), "{e}");
    }
}
