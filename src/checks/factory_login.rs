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
    rc.code_only().max_time(15)
}

pub fn judge(out: &Output, reject: &[u16]) -> Verdict {
    if out.code != Some(0) {
        return Verdict::CannotMeasure(format!(
            "curl exit {:?}: {}",
            out.code,
            out.stderr.trim().lines().next().unwrap_or("")
        ));
    }
    let code: u16 = match out.stdout.trim().parse() {
        Ok(c) => c,
        Err(_) => {
            return Verdict::CannotMeasure(format!(
                "curl printed {:?} instead of a status",
                out.stdout.trim()
            ));
        }
    };
    if reject.contains(&code) {
        Verdict::Ok(format!("HTTP {code}: factory account rejected"))
    } else if code == 200 {
        Verdict::Failed("factory account ACCEPTED (HTTP 200) — the door is open".into())
    } else {
        Verdict::Failed(format!("unexpected HTTP {code} — the probe proves nothing"))
    }
}

pub fn check(r: &dyn Runner, s: &Service) -> Verdict {
    let Some(f) = &s.factory_login else {
        return Verdict::Undeclared("no probe in lib/werkskonten.nix".into());
    };
    let Some(backend) = &s.backend else {
        return Verdict::CannotMeasure("factory_login declared but no backend".into());
    };
    match guest::host_curl_in_netns(r, &s.guest, &rc(backend, f)) {
        Ok(out) => judge(&out, &f.reject),
        Err(e) => Verdict::CannotMeasure(e),
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
        };
        let text = String::from_utf8(rc("10.0.120.10:28981", &f).render()).unwrap();
        assert!(text.contains("user = \"admin:admin\"\n"));
        assert!(!text.contains("request ="));
    }

    #[test]
    fn rejected_is_ok_accepted_is_the_finding_anything_else_proves_nothing() {
        assert_eq!(
            judge(&out(0, "401", ""), &[401, 403]),
            Verdict::Ok("HTTP 401: factory account rejected".into())
        );
        assert_eq!(
            judge(&out(0, "200", ""), &[401, 403]),
            Verdict::Failed("factory account ACCEPTED (HTTP 200) — the door is open".into())
        );
        assert_eq!(
            judge(&out(0, "500", ""), &[401, 403]),
            Verdict::Failed("unexpected HTTP 500 — the probe proves nothing".into())
        );
        assert!(matches!(
            judge(&out(7, "000", "curl: (7) Failed to connect"), &[401]),
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
