//! Does the vendor's default account still log in? The door is TRIED, not
//! asked about: a setting that says "registration disabled" has been wrong
//! here before. Run in the service guest's NETWORK against the zone address,
//! never through the public name (the identity provider sits in front).
//!
//! Seit v0.2.0 mit dem curl des WIRTS (`guest::host_curl_in_netns`), nicht
//! mehr mit dem des Gastes (Audit 3, B113): Das Urteil soll auch gegen einen
//! uebernommenen Gast etwas belegen.

use crate::config::{FactoryLogin, Service};
use crate::curlrc::CurlRc;
use crate::guest;
use crate::runner::{Output, Runner};
use crate::verdict::Verdict;

pub fn rc(backend: &str, f: &FactoryLogin) -> CurlRc {
    let mut rc = CurlRc::new(&format!("http://{backend}{}", f.path));
    if f.method != "GET" {
        rc = rc.request(&f.method);
    }
    if let Some(ct) = &f.content_type {
        rc = rc.header("Content-Type", ct);
    }
    if let Some(body) = &f.body {
        rc = rc.data(body);
    }
    if let (Some(u), Some(p)) = (&f.user, &f.password) {
        rc = rc.user(u, p);
    }
    // With `reject_body` the answer is decided by what the body says, so the
    // body has to come back; without it only the status does.
    if f.reject_body.is_some() {
        rc.body_then_code().max_time(15)
    } else {
        rc.code_only().max_time(15)
    }
}

/// What `Verdict::Undeclared` says by default, and what it says in strict
/// mode (`undeclared_is_failure`), where it is a finding.
pub const UNDECLARED: &str = "no probe in lib/werkskonten.nix";
pub const UNDECLARED_STRICT: &str = "neither a factory_login probe nor a no_factory_login reason is declared (undeclared_is_failure)";

/// `reject_body`: `None` — the status alone decides, as before. `Some` —
/// stdout is the body followed by the status on a last line of its own
/// (`CurlRc::body_then_code`), and a status in `reject` only counts when
/// the body contains the substring.
///
/// The body itself never goes into a verdict: a login that was ACCEPTED
/// answers with a session token, and the report ends up in a terminal, the
/// journal and an alert mail. Its length is all that is said about it.
pub fn judge(out: &Output, reject: &[u16], reject_body: Option<&str>) -> Verdict {
    if out.code != Some(0) {
        return Verdict::CannotMeasure(format!(
            "curl exit {:?}: {}",
            out.code,
            out.stderr.trim().lines().next().unwrap_or("")
        ));
    }
    let (body, status) = match reject_body {
        None => (None, out.stdout.trim()),
        Some(_) => match out.stdout.rsplit_once('\n') {
            Some((body, status)) => (Some(body), status.trim()),
            None => (Some(out.stdout.as_str()), ""),
        },
    };
    let code: u16 = match status.parse() {
        Ok(c) => c,
        Err(_) => {
            return Verdict::CannotMeasure(match body {
                None => format!("curl printed {status:?} instead of a status"),
                Some(_) => format!(
                    "curl printed no status after the body ({} bytes of output)",
                    out.stdout.len()
                ),
            });
        }
    };
    if !reject.contains(&code) {
        return if code == 200 {
            Verdict::Failed("factory account ACCEPTED (HTTP 200) — the door is open".into())
        } else {
            Verdict::Failed(format!("unexpected HTTP {code} — the probe proves nothing"))
        };
    }
    match (body, reject_body) {
        (Some(body), Some(expected)) if !body.contains(expected) => Verdict::Failed(format!(
            "HTTP {code}, but the body ({} bytes) lacks the expected rejection text — the door may be open",
            body.len()
        )),
        (Some(_), Some(_)) => Verdict::Ok(format!(
            "HTTP {code} with the expected rejection text: factory account rejected"
        )),
        _ => Verdict::Ok(format!("HTTP {code}: factory account rejected")),
    }
}

pub fn check(r: &dyn Runner, s: &Service) -> Verdict {
    // The written-down exception: nothing to try, and somebody said why.
    if let Some(reason) = &s.no_factory_login {
        return Verdict::NotApplicable(reason.clone());
    }
    let Some(f) = &s.factory_login else {
        return Verdict::Undeclared(UNDECLARED.into());
    };
    let Some(backend) = &s.backend else {
        return Verdict::CannotMeasure("factory_login declared but no backend".into());
    };
    // `Limits::GUEST` (inside `host_curl_in_netns`) caps the body: a service
    // that answers with more than 1 MiB is `cannot measure`, not a full heap.
    match guest::host_curl_in_netns(r, &s.guest, &rc(backend, f)) {
        Ok(out) => judge(&out, &f.reject, f.reject_body.as_deref()),
        Err(e) => Verdict::CannotMeasure(e),
    }
}

/// Strict mode: `undeclared` becomes a finding. Every other verdict passes
/// through untouched — in particular the `n/a` of a declared exception.
pub fn strict(v: Verdict, undeclared_is_failure: bool) -> Verdict {
    match v {
        Verdict::Undeclared(_) if undeclared_is_failure => {
            Verdict::Failed(UNDECLARED_STRICT.into())
        }
        v => v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, parse};
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
    fn rc_builds_the_declared_request_against_the_backend() {
        let c = cfg();
        let s = c.service("ghostfolio").unwrap();
        let text = String::from_utf8(
            rc(
                s.backend.as_deref().unwrap(),
                s.factory_login.as_ref().unwrap(),
            )
            .render(),
        )
        .unwrap();
        assert!(text.starts_with("url = \"http://10.0.190.10:3333/api/auth/token\"\n"));
        assert!(text.contains("request = \"POST\"\n"));
        assert!(text.contains("header = \"Content-Type: application/x-www-form-urlencoded\"\n"));
        assert!(text.contains("data = \"username=changeme%40example.com&password=MyPassword\"\n"));
        assert!(text.contains("write-out = \"%{http_code}\"\n"));
        assert!(text.ends_with("max-time = 15\n"));
    }

    #[test]
    fn basic_auth_probe_uses_user_and_no_request_line_for_get() {
        let f = FactoryLogin {
            method: "GET".into(),
            path: "/api/documents/".into(),
            content_type: None,
            body: None,
            user: Some("admin".into()),
            password: Some("admin".into()),
            reject: vec![401, 403],
            reject_body: None,
        };
        let text = String::from_utf8(rc("10.0.120.10:28981", &f).render()).unwrap();
        assert!(text.contains("user = \"admin:admin\"\n"));
        assert!(!text.contains("request ="));
    }

    #[test]
    fn rejected_is_ok_accepted_is_the_finding_anything_else_proves_nothing() {
        assert_eq!(
            judge(&out(0, "401", ""), &[401, 403], None),
            Verdict::Ok("HTTP 401: factory account rejected".into())
        );
        assert_eq!(
            judge(&out(0, "200", ""), &[401, 403], None),
            Verdict::Failed("factory account ACCEPTED (HTTP 200) — the door is open".into())
        );
        assert_eq!(
            judge(&out(0, "500", ""), &[401, 403], None),
            Verdict::Failed("unexpected HTTP 500 — the probe proves nothing".into())
        );
        assert!(matches!(
            judge(&out(7, "000", "curl: (7) Failed to connect"), &[401], None),
            Verdict::CannotMeasure(_)
        ));
    }

    #[test]
    fn check_runs_in_the_service_guest_and_reports_undeclared() {
        let c = cfg();
        let fake = Fake::new()
            .on(
                "machinectl",
                "fin-01 --property=Leader",
                out(0, "4242\n", ""),
            )
            .on("nsenter", "-t 4242 -n -- curl", out(0, "403", ""));
        assert_eq!(
            check(&fake, c.service("ghostfolio").unwrap()),
            Verdict::Ok("HTTP 403: factory account rejected".into())
        );
        assert_eq!(
            check(&fake, c.service("radarr").unwrap()),
            Verdict::Undeclared("no probe in lib/werkskonten.nix".into())
        );
    }

    /// qBittorrent answers a wrong login with HTTP 200 and `Fails.`, a right
    /// one with HTTP 200 and `Ok.` — the status says nothing.
    #[test]
    fn with_reject_body_the_status_alone_does_not_reject() {
        let fails = Some("Fails.");
        assert_eq!(
            judge(&out(0, "Fails.\n200", ""), &[200], fails),
            Verdict::Ok(
                "HTTP 200 with the expected rejection text: factory account rejected".into()
            )
        );
        assert_eq!(
            judge(&out(0, "Ok.\n200", ""), &[200], fails),
            Verdict::Failed(
                "HTTP 200, but the body (3 bytes) lacks the expected rejection text — the door may be open".into()
            )
        );
        // An empty body lacks the text, too.
        assert_eq!(
            judge(&out(0, "\n200", ""), &[200], fails),
            Verdict::Failed(
                "HTTP 200, but the body (0 bytes) lacks the expected rejection text — the door may be open".into()
            )
        );
        // A body of several lines: only the LAST line is the status.
        assert_eq!(
            judge(
                &out(0, "<html>\n401\nFails.\n</html>\n200", ""),
                &[200],
                fails
            ),
            Verdict::Ok(
                "HTTP 200 with the expected rejection text: factory account rejected".into()
            )
        );
        // A status outside `reject` is judged as before, whatever the body.
        assert_eq!(
            judge(&out(0, "Fails.\n500", ""), &[200], fails),
            Verdict::Failed("unexpected HTTP 500 — the probe proves nothing".into())
        );
        assert_eq!(
            judge(&out(0, "Fails.\n200", ""), &[401, 403], fails),
            Verdict::Failed("factory account ACCEPTED (HTTP 200) — the door is open".into())
        );
    }

    #[test]
    fn the_body_never_reaches_a_verdict() {
        let secret = "{\"authToken\":\"s3cr3t-session-token\"}";
        for stdout in [
            format!("{secret}\n200"),
            // No status line at all: the old message quoted stdout.
            secret.to_string(),
            format!("{secret}\nnot-a-status"),
        ] {
            let v = judge(&out(0, &stdout, ""), &[200], Some("Fails."));
            assert!(!v.detail().contains("s3cr3t"), "{v:?}");
            assert!(!v.detail().contains("authToken"), "{v:?}");
            assert_ne!(v.label(), "ok", "{v:?}");
        }
        assert_eq!(
            judge(&out(0, secret, ""), &[200], Some("Fails.")),
            Verdict::CannotMeasure(
                "curl printed no status after the body (36 bytes of output)".into()
            )
        );
    }

    #[test]
    fn rc_asks_for_the_body_only_when_reject_body_is_declared() {
        let c = cfg();
        let mut f = c
            .service("ghostfolio")
            .unwrap()
            .factory_login
            .clone()
            .unwrap();
        let text = String::from_utf8(rc("10.0.190.10:3333", &f).render()).unwrap();
        assert!(text.contains("output = \"/dev/null\"\n"), "{text}");
        f.reject_body = Some("Fails.".into());
        let text = String::from_utf8(rc("10.0.190.10:3333", &f).render()).unwrap();
        assert!(!text.contains("output ="), "{text}");
        assert!(text.contains("write-out = \"\\n%{http_code}\"\n"), "{text}");
        assert!(text.ends_with("max-time = 15\n"), "{text}");
        // The expected text is the judge's business, not curl's.
        assert!(!text.contains("Fails."), "{text}");
    }

    #[test]
    fn a_declared_exception_is_not_applicable_with_its_reason_and_runs_nothing() {
        let c = cfg();
        let mut s = c.service("radarr").unwrap().clone();
        s.no_factory_login = Some("local login is disabled, OIDC only".into());
        let fake = Fake::new();
        assert_eq!(
            check(&fake, &s),
            Verdict::NotApplicable("local login is disabled, OIDC only".into())
        );
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn strict_turns_only_undeclared_into_a_finding() {
        let undeclared = Verdict::Undeclared(UNDECLARED.into());
        assert_eq!(strict(undeclared.clone(), false), undeclared);
        assert_eq!(
            strict(undeclared, true),
            Verdict::Failed(UNDECLARED_STRICT.into())
        );
        for v in [
            Verdict::Ok("HTTP 401: factory account rejected".into()),
            Verdict::NotApplicable("no account".into()),
            Verdict::CannotMeasure("curl exit Some(7): x".into()),
        ] {
            assert_eq!(strict(v.clone(), true), v);
        }
    }

    #[test]
    fn factory_login_without_a_running_guest_is_cannot_measure() {
        let c = cfg();
        let fake = Fake::new().on(
            "machinectl",
            "fin-01",
            out(
                1,
                "",
                "Could not get path to machine: No machine 'fin-01' known",
            ),
        );
        let v = check(&fake, c.service("ghostfolio").unwrap());
        assert_eq!(
            v,
            Verdict::CannotMeasure(
                "machinectl names no leader for fin-01 (exit Some(1)): Could not get path to machine: No machine 'fin-01' known".into()
            )
        );
    }

    #[test]
    fn declared_probe_without_backend_is_cannot_measure() {
        let c = cfg();
        let mut s = c.service("ghostfolio").unwrap().clone();
        s.backend = None;
        assert_eq!(
            check(&Fake::new(), &s),
            Verdict::CannotMeasure("factory_login declared but no backend".into())
        );
    }
}
