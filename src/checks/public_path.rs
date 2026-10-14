//! Does the public listener carry the name? The router forwards public :443
//! to `public_endpoint` (Caddy in `caddy_guest`); this check connects there
//! with the HOST's curl inside that guest's network namespace
//! (`guest::host_curl_in_netns`), `resolve` forcing both the SNI and the
//! target. Any HTTP status means Caddy holds a certificate for the name and
//! answered; curl exit 35 "tlsv1 alert internal error" is Caddy refusing a
//! handshake for a name it has no certificate for.
//!
//! NOT measured: the router's DNAT and the way in from outside. The host
//! has no firewall edge to the public listener (measured 2026-10-14), so
//! the probe stands where Caddy stands; whether the forward from the
//! router carries is a question for a probe from outside.

use crate::config::{Config, Service};
use crate::curlrc::CurlRc;
use crate::guest;
use crate::runner::{Output, Runner};
use crate::verdict::Verdict;

/// What Caddy's refusal looks like in curl's stderr (OpenSSL 3, measured
/// 2026-10-14 in the network of infra-01 with an invented name).
pub const CADDY_REFUSES: &str = "tlsv1 alert internal error";
const NOT_SERVED: &str = "TLS handshake refused by Caddy (no certificate for the name): the name is not served on the public listener";

/// The probe, as a curl config for stdin. `None`: `public_endpoint` is not
/// `ip:port` (unreachable after `config::parse`).
pub fn rc(host: &str, cfg: &Config) -> Option<CurlRc> {
    let (ip, port) = cfg.public_endpoint_parts()?;
    Some(
        CurlRc::new(&format!("https://{host}:{port}/"))
            .resolve(host, port, ip)
            .code_only()
            .max_time(15),
    )
}

fn first_line(s: &str) -> &str {
    s.trim().lines().next().unwrap_or("")
}

pub fn judge(out: &Output, endpoint: &str) -> Verdict {
    match out.code {
        Some(0) => Verdict::Ok(format!("HTTP {} via {endpoint}", out.stdout.trim())),
        Some(35) if out.stderr.contains(CADDY_REFUSES) => Verdict::Failed(NOT_SERVED.into()),
        Some(35) => Verdict::Failed(format!("TLS error: {}", first_line(&out.stderr))),
        // 60: the certificate cannot be verified, 51: it does not name the
        // host. The path carried — what came back is wrong: a finding.
        Some(code @ (51 | 60)) => Verdict::Failed(format!(
            "TLS certificate problem (curl exit {code}): {}",
            first_line(&out.stderr)
        )),
        Some(code) => {
            Verdict::CannotMeasure(format!("curl exit {code}: {}", first_line(&out.stderr)))
        }
        None => Verdict::CannotMeasure("curl killed by a signal".into()),
    }
}

fn probe(r: &dyn Runner, cfg: &Config, host: &str) -> Result<Output, String> {
    let rc = rc(host, cfg)
        .ok_or_else(|| format!("public_endpoint {:?} is not ip:port", cfg.public_endpoint))?;
    guest::host_curl_in_netns(r, &cfg.caddy_guest, &rc)
}

pub fn check(r: &dyn Runner, cfg: &Config, s: &Service) -> Verdict {
    if !s.public {
        return Verdict::NotApplicable("not public".into());
    }
    match probe(r, cfg, &s.host) {
        Ok(out) => judge(&out, &cfg.public_endpoint),
        Err(e) => Verdict::CannotMeasure(e),
    }
}

/// An invented name MUST be refused. If it is not, an answer for a real
/// name cannot tell a certificate of its own from a catch-all.
pub fn control_canary(r: &dyn Runner, cfg: &Config) -> Result<(), String> {
    let name = format!(
        "signoff-canary-{}-{}.{}",
        crate::time::now(),
        std::process::id(),
        cfg.zone
    );
    let out = probe(r, cfg, &name)?;
    match judge(&out, &cfg.public_endpoint) {
        Verdict::Failed(d) if d == NOT_SERVED => Ok(()),
        Verdict::Ok(d) => Err(format!(
            "control: the public listener accepted the invented name {name} ({d}) — a 200 would prove nothing"
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

    const EP: &str = "10.0.20.11:8443";

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
    /// infra-01 hat den Leader 1111; `nsenter` antwortet `antwort`.
    fn caddy(antwort: Output) -> Fake {
        Fake::new()
            .on(
                "machinectl",
                "infra-01 --property=Leader",
                out(0, "1111\n", ""),
            )
            .on("nsenter", "-t 1111 -n", antwort)
    }

    #[test]
    fn rc_forces_sni_and_target_on_the_public_endpoint() {
        let text =
            String::from_utf8(rc("ghostfolio.rusty-vault.de", &cfg()).unwrap().render()).unwrap();
        assert_eq!(
            text,
            "url = \"https://ghostfolio.rusty-vault.de:8443/\"\nresolve = \"ghostfolio.rusty-vault.de:8443:10.0.20.11\"\nsilent\nshow-error\noutput = \"/dev/null\"\nwrite-out = \"%{http_code}\"\nmax-time = 15\n"
        );
    }

    #[test]
    fn any_http_answer_is_ok_with_the_status() {
        for code in ["302", "404", "200"] {
            assert_eq!(
                judge(&out(0, code, ""), EP),
                Verdict::Ok(format!("HTTP {code} via {EP}"))
            );
        }
    }

    #[test]
    fn caddys_refusal_is_the_not_served_finding() {
        let v = judge(
            &out(
                35,
                "000",
                include_str!("../../tests/answers/curl-35-caddy-internal-error.txt"),
            ),
            EP,
        );
        assert_eq!(v, Verdict::Failed(NOT_SERVED.into()));
    }

    #[test]
    fn other_tls_errors_are_findings_with_curls_line() {
        let v = judge(&out(35, "000", "curl: (35) alert handshake failure"), EP);
        assert_eq!(
            v,
            Verdict::Failed("TLS error: curl: (35) alert handshake failure".into())
        );
    }

    #[test]
    fn certificate_problems_are_findings_not_cannot_measure() {
        for (code, msg) in [
            (
                60,
                "curl: (60) SSL certificate problem: self-signed certificate",
            ),
            (
                51,
                "curl: (51) SSL: no alternative certificate subject name matches target hostname 'x.rusty-vault.de'",
            ),
        ] {
            assert_eq!(
                judge(&out(code, "000", msg), EP),
                Verdict::Failed(format!("TLS certificate problem (curl exit {code}): {msg}"))
            );
        }
    }

    #[test]
    fn public_path_unreachable_is_cannot_measure() {
        for (code, msg) in [
            (7, "curl: (7) Failed to connect"),
            (28, "curl: (28) Connection timed out"),
            (6, "curl: (6) Could not resolve host"),
        ] {
            let v = judge(&out(code, "000", msg), EP);
            assert_eq!(
                v,
                Verdict::CannotMeasure(format!("curl exit {code}: {msg}"))
            );
        }
    }

    #[test]
    fn check_runs_the_hosts_curl_in_the_network_of_the_caddy_guest() {
        let c = cfg();
        let fake = caddy(out(0, "302", ""));
        assert_eq!(
            check(&fake, &c, c.service("ghostfolio").unwrap()),
            Verdict::Ok(format!("HTTP 302 via {EP}"))
        );
        let calls = fake.calls();
        assert_eq!(calls.len(), 2);
        let (prog, argv, stdin) = &calls[1];
        assert_eq!(prog, "nsenter");
        assert_eq!(argv, &["-t", "1111", "-n", "--", "curl", "-K", "-"]);
        let rc = String::from_utf8(stdin.clone().unwrap()).unwrap();
        assert!(
            rc.contains("resolve = \"ghostfolio.rusty-vault.de:8443:10.0.20.11\""),
            "{rc}"
        );
        // Nichts davon in argv.
        assert!(!argv.join(" ").contains("rusty-vault.de"));
    }

    #[test]
    fn check_skips_internal_services_and_names_a_missing_namespace() {
        let c = cfg();
        let fake = Fake::new();
        assert_eq!(
            check(&fake, &c, c.service("radarr").unwrap()),
            Verdict::NotApplicable("not public".into())
        );
        assert!(fake.calls().is_empty());
        let ohne_leader = Fake::new().on("machinectl", "", out(1, "", "No machine"));
        let v = check(&ohne_leader, &c, c.service("ghostfolio").unwrap());
        assert!(
            matches!(&v, Verdict::CannotMeasure(d) if d.contains("no leader for infra-01")),
            "{v:?}"
        );
    }

    #[test]
    fn canary_control_passes_only_when_caddy_refuses_the_invented_name() {
        let c = cfg();
        let rejects = caddy(out(
            35,
            "000",
            include_str!("../../tests/answers/curl-35-caddy-internal-error.txt"),
        ));
        assert!(control_canary(&rejects, &c).is_ok());
        let rc = String::from_utf8(rejects.calls()[1].2.clone().unwrap()).unwrap();
        assert!(rc.contains("signoff-canary-"), "{rc}");
        assert!(rc.contains(".rusty-vault.de:8443:10.0.20.11\""), "{rc}");

        let accepts = caddy(out(0, "200", ""));
        let e = control_canary(&accepts, &c).unwrap_err();
        assert!(e.contains("a 200 would prove nothing"), "{e}");
        // Eine andere TLS-Ablehnung ist nicht Caddys Befund: nicht belegt.
        let anders = caddy(out(35, "000", "curl: (35) alert handshake failure"));
        assert!(
            control_canary(&anders, &c)
                .unwrap_err()
                .contains("TLS error")
        );
        let down = caddy(out(7, "000", "curl: (7) Failed to connect"));
        assert!(control_canary(&down, &c).unwrap_err().contains("exit 7"));
        let ohne_setns = caddy(out(
            1,
            "",
            "nsenter: reassociate to namespace 'ns/net' failed: Operation not permitted\n",
        ));
        assert!(
            control_canary(&ohne_setns, &c)
                .unwrap_err()
                .contains("cannot enter the network namespace of infra-01")
        );
    }
}
