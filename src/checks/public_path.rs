//! Does the public path carry the name home? `curl --resolve` forces both
//! the SNI and the target, so the answer comes from the VPS's stream map:
//! any HTTP status means the home reverse proxy answered; curl exit 35
//! "unrecognized name" is the VPS's default vhost refusing the handshake.

use crate::config::{Config, Service};
use crate::runner::{Output, Runner};
use crate::verdict::Verdict;

pub const CURL: &str = "curl";

pub fn args(host: &str, vps_v4: &str) -> Vec<String> {
    vec![
        "-sS".into(),
        "-o".into(),
        "/dev/null".into(),
        "--max-time".into(),
        "15".into(),
        "--resolve".into(),
        format!("{host}:443:{vps_v4}"),
        "-w".into(),
        "%{http_code}".into(),
        format!("https://{host}/"),
    ]
}

fn first_line(s: &str) -> &str {
    s.trim().lines().next().unwrap_or("")
}

pub fn judge(out: &Output, vps_v4: &str) -> Verdict {
    match out.code {
        Some(0) => Verdict::Ok(format!("HTTP {} via {vps_v4}", out.stdout.trim())),
        Some(35) if out.stderr.contains("unrecognized name") => Verdict::Failed(
            "TLS handshake rejected by the VPS default vhost (unrecognized name): the name is not in the SNI map — just deploy-vps?".into(),
        ),
        Some(35) => Verdict::Failed(format!("TLS error: {}", first_line(&out.stderr))),
        Some(code) => Verdict::CannotMeasure(format!("curl exit {code}: {}", first_line(&out.stderr))),
        None => Verdict::CannotMeasure("curl killed by a signal".into()),
    }
}

pub fn check(r: &dyn Runner, cfg: &Config, s: &Service) -> Verdict {
    if !s.public {
        return Verdict::NotApplicable("not public".into());
    }
    match r.run(CURL, &args(&s.host, &cfg.vps_v4), None) {
        Ok(out) => judge(&out, &cfg.vps_v4),
        Err(e) => Verdict::CannotMeasure(e),
    }
}

/// An invented name MUST be refused. If it is not, a 200 for a real name
/// cannot tell an SNI-map entry from a catch-all.
pub fn control_canary(r: &dyn Runner, cfg: &Config) -> Result<(), String> {
    let name = format!(
        "signoff-canary-{}-{}.{}",
        crate::time::now(),
        std::process::id(),
        cfg.zone
    );
    let out = r.run(CURL, &args(&name, &cfg.vps_v4), None)?;
    match judge(&out, &cfg.vps_v4) {
        Verdict::Failed(d) if d.contains("unrecognized name") => Ok(()),
        Verdict::Ok(d) => Err(format!(
            "control: the VPS accepted the invented name {name} ({d}) — a 200 would prove nothing"
        )),
        other => Err(format!(
            "control: canary {name}: {} {}",
            other.label(),
            other.detail()
        )),
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
    fn args_force_sni_and_target() {
        let a = args("ghostfolio.rusty-vault.de", "77.42.71.141");
        assert!(a.contains(&"ghostfolio.rusty-vault.de:443:77.42.71.141".to_string()));
        assert_eq!(a.last().unwrap(), "https://ghostfolio.rusty-vault.de/");
        assert!(a.contains(&"--resolve".to_string()));
    }

    #[test]
    fn any_http_answer_is_ok_with_the_status() {
        assert_eq!(
            judge(&out(0, "302", ""), "77.42.71.141"),
            Verdict::Ok("HTTP 302 via 77.42.71.141".into())
        );
        assert_eq!(
            judge(&out(0, "200", ""), "77.42.71.141"),
            Verdict::Ok("HTTP 200 via 77.42.71.141".into())
        );
    }

    #[test]
    fn unrecognized_name_is_the_sni_map_finding() {
        let v = judge(
            &out(
                35,
                "000",
                include_str!("../../tests/answers/curl-35-unrecognized.txt"),
            ),
            "77.42.71.141",
        );
        assert_eq!(
            v,
            Verdict::Failed(
                "TLS handshake rejected by the VPS default vhost (unrecognized name): the name is not in the SNI map — just deploy-vps?".into()
            )
        );
    }

    #[test]
    fn other_tls_errors_are_findings_with_curls_line() {
        let v = judge(
            &out(35, "000", "curl: (35) alert handshake failure"),
            "77.42.71.141",
        );
        assert_eq!(
            v,
            Verdict::Failed("TLS error: curl: (35) alert handshake failure".into())
        );
    }

    #[test]
    fn public_path_unreachable_is_cannot_measure() {
        for (code, msg) in [
            (7, "curl: (7) Failed to connect"),
            (28, "curl: (28) Connection timed out"),
            (6, "curl: (6) Could not resolve host"),
        ] {
            let v = judge(&out(code, "000", msg), "77.42.71.141");
            assert_eq!(
                v,
                Verdict::CannotMeasure(format!("curl exit {code}: {msg}"))
            );
        }
    }

    #[test]
    fn check_uses_the_service_host_and_skips_internal_services() {
        let c = cfg();
        let fake = Fake::new().on(
            "curl",
            "https://ghostfolio.rusty-vault.de/",
            out(0, "302", ""),
        );
        assert_eq!(
            check(&fake, &c, c.service("ghostfolio").unwrap()),
            Verdict::Ok("HTTP 302 via 77.42.71.141".into())
        );
        assert_eq!(
            check(&fake, &c, c.service("radarr").unwrap()),
            Verdict::NotApplicable("not public".into())
        );
    }

    #[test]
    fn canary_control_passes_only_when_the_vps_rejects_the_invented_name() {
        let c = cfg();
        let rejects = Fake::new().on(
            "curl",
            "signoff-canary-",
            out(
                35,
                "000",
                include_str!("../../tests/answers/curl-35-unrecognized.txt"),
            ),
        );
        assert!(control_canary(&rejects, &c).is_ok());
        let accepts = Fake::new().on("curl", "signoff-canary-", out(0, "200", ""));
        let e = control_canary(&accepts, &c).unwrap_err();
        assert!(e.contains("a 200 would prove nothing"), "{e}");
        let down = Fake::new().on(
            "curl",
            "signoff-canary-",
            out(7, "000", "curl: (7) Failed to connect"),
        );
        assert!(control_canary(&down, &c).unwrap_err().contains("exit 7"));
    }
}
