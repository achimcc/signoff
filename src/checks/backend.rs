//! Can the reverse proxy reach the service? `vantage probe` runs curl
//! inside the proxy's guest and tells a drop at the zone edge from a
//! refusal or a drop elsewhere — the verdict words are vantage's.

use crate::config::{Config, Service};
use crate::runner::{Output, Runner};
use crate::verdict::Verdict;

pub const VANTAGE: &str = "vantage";

pub fn args(from: &str, guest: &str, port: u16) -> Vec<String> {
    vec![
        "probe".into(),
        "--from".into(),
        from.into(),
        format!("{guest}:{port}"),
    ]
}

/// `vantage: probe A (ip) -> B (ip):PORT/path sport N: <verdict…>`
fn split(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("vantage: probe ")?;
    let (head, verdict) = rest.split_once(": ")?;
    let (from, to) = head.split_once(" -> ")?;
    let from = from.split(' ').next()?;
    let (to_name, tail) = to.split_once(" (")?;
    let port = tail.split_once("):")?.1.split('/').next()?;
    Some((format!("{from} -> {to_name}:{port}"), verdict.to_string()))
}

pub fn judge(out: &Output) -> Verdict {
    if out.code == Some(2) {
        return Verdict::CannotMeasure(
            out.stderr
                .trim()
                .lines()
                .next()
                .unwrap_or("vantage exit 2")
                .to_string(),
        );
    }
    let line = out
        .stdout
        .lines()
        .find(|l| l.starts_with("vantage: probe "))
        .unwrap_or("");
    let Some((path, verdict)) = split(line) else {
        return Verdict::CannotMeasure(format!(
            "vantage said something unexpected: {}",
            out.stdout.trim().lines().next().unwrap_or("")
        ));
    };
    if let Some(status) = verdict.strip_prefix("answered") {
        return Verdict::Ok(format!("answered{status} ({path})"));
    }
    if verdict.starts_with("dropped at zone edge") {
        return Verdict::Failed(format!(
            "dropped at zone edge ({path}): the edge {path} is missing from `erreicht`"
        ));
    }
    if verdict.starts_with("dropped elsewhere") {
        return Verdict::Failed(format!(
            "dropped elsewhere ({path}): the source's egress lock or the target's own firewall"
        ));
    }
    if verdict.starts_with("refused") {
        return Verdict::Failed(format!(
            "refused ({path}): nothing listens or the guest firewall rejects"
        ));
    }
    Verdict::CannotMeasure(format!("vantage: {verdict}"))
}

pub fn check(r: &dyn Runner, cfg: &Config, s: &Service) -> Verdict {
    let (Some(backend), Some(port)) = (&s.backend, s.backend_port()) else {
        return Verdict::NotApplicable("no backend".into());
    };
    let Some(guest) = &s.backend_guest else {
        let ip = backend
            .rsplit_once(':')
            .map_or(backend.as_str(), |(ip, _)| ip);
        return Verdict::CannotMeasure(format!("backend {ip} is not a declared guest"));
    };
    match r.run(VANTAGE, &args(&cfg.caddy_guest, guest, port), None) {
        Ok(out) => judge(&out),
        Err(e) => Verdict::CannotMeasure(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;
    use crate::runner::{Fake, Output};

    fn cfg() -> Config {
        parse(include_str!("../../tests/answers/signoff.toml")).unwrap()
    }
    fn out(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn args_name_source_guest_target_guest_and_port() {
        assert_eq!(
            args("infra-01", "fin-01", 3333),
            vec!["probe", "--from", "infra-01", "fin-01:3333"]
        );
    }

    #[test]
    fn answered_is_ok_with_the_status() {
        let v = judge(&out(
            0,
            include_str!("../../tests/answers/vantage-answered.txt"),
            "",
        ));
        assert_eq!(
            v,
            Verdict::Ok("answered 301 (infra-01 -> fin-01:3333)".into())
        );
    }

    #[test]
    fn dropped_and_refused_are_findings_with_vantages_words() {
        let v = judge(&out(
            1,
            include_str!("../../tests/answers/vantage-edge.txt"),
            "",
        ));
        assert_eq!(
            v,
            Verdict::Failed(
                "dropped at zone edge (infra-01 -> fin-01:3334): the edge infra-01 -> fin-01:3334 is missing from `erreicht`".into()
            )
        );
        let v = judge(&out(
            1,
            "vantage: probe a (1) -> b (2):80/ sport 1: refused (connection refused)",
            "",
        ));
        assert_eq!(
            v,
            Verdict::Failed(
                "refused (a -> b:80): nothing listens or the guest firewall rejects".into()
            )
        );
        let v = judge(&out(
            1,
            "vantage: probe a (1) -> b (2):80/ sport 1: dropped elsewhere — the source's egress lock",
            "",
        ));
        assert_eq!(
            v,
            Verdict::Failed(
                "dropped elsewhere (a -> b:80): the source's egress lock or the target's own firewall".into()
            )
        );
    }

    #[test]
    fn tool_error_is_cannot_measure() {
        let v = judge(&out(
            2,
            "",
            "vantage: curl is not in the profile of the source guest",
        ));
        assert_eq!(
            v,
            Verdict::CannotMeasure(
                "vantage: curl is not in the profile of the source guest".into()
            )
        );
        let v = judge(&out(0, "something new", ""));
        assert!(matches!(v, Verdict::CannotMeasure(_)));
    }

    #[test]
    fn check_probes_from_the_caddy_guest_or_says_why_not() {
        let c = cfg();
        let fake = Fake::new().on(
            "vantage",
            "--from infra-01 fin-01:3333",
            out(
                0,
                include_str!("../../tests/answers/vantage-answered.txt"),
                "",
            ),
        );
        assert!(matches!(
            check(&fake, &c, c.service("ghostfolio").unwrap()),
            Verdict::Ok(_)
        ));
        assert_eq!(
            check(&fake, &c, c.service("start").unwrap()),
            Verdict::NotApplicable("no backend".into())
        );
        let mut s = c.service("radarr").unwrap().clone();
        s.backend_guest = None;
        assert_eq!(
            check(&fake, &c, &s),
            Verdict::CannotMeasure("backend 10.0.10.10 is not a declared guest".into())
        );
    }
}
