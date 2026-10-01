//! Audit 3 (homeserver, 2026-09-27), finding B143: `factory-login` could
//! only say `undeclared` for a service without a probe, could not tell a
//! refused login from an accepted one where both answer HTTP 200, and an
//! `undeclared` never turned a run red.
//!
//! Every case goes through the configuration text and `app::check`, the
//! way a run on the host does — so each of them is red against 0.2.0,
//! which refuses the new fields outright.

use signoff::app;
use signoff::config::{Config, parse};
use signoff::runner::{Fake, Limits, Output};

fn out(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        code: Some(code),
        stdout: stdout.into(),
        stderr: stderr.into(),
    }
}

/// One internal service (qBittorrent behind no forward-auth), with `top`
/// in front of the top-level fields and `service` appended to the entry.
fn toml(top: &str, service: &str) -> String {
    format!(
        r#"{top}
zone = "rusty-vault.de"
resolver = "1.1.1.1"
vps_v4 = "77.42.71.141"
vps_v6 = "2a01:4f9:c013:5ee7::1"
caddy_guest = "infra-01"
auth_guest = "auth-01"
auth_api = "http://127.0.0.1:9000/api/v3"
outpost = "authentik Embedded Outpost"
rustic_profile = "/etc/rustic/rustic"
snapshot_max_age_hours = 48

[[service]]
key = "qbittorrent"
host = "qbittorrent.rusty-vault.de"
guest = "dl-01"
public = false
backend = "10.0.20.10:8080"
backend_guest = "dl-01"
forward_auth = false
dataset = "rpool/guests/fin-01"
{service}
"#
    )
}

const PROBE: &str = r#"
[service.factory_login]
method = "POST"
path = "/api/v2/auth/login"
content_type = "application/x-www-form-urlencoded"
body = "username=admin&password=adminadmin"
reject = [200]
reject_body = "Fails."
"#;

/// A host where everything but `factory-login` is in order; the service's
/// own answer to the login attempt is `login`.
fn host(login: Output) -> Fake {
    Fake::new()
        .on("dig", "SOA", out(0, "ns. hostmaster. 1 2 3 4 5\n", ""))
        .on(
            "curl",
            "signoff-canary-",
            out(35, "000", include_str!("answers/curl-35-unrecognized.txt")),
        )
        .on(
            "vantage",
            "probe",
            out(0, include_str!("answers/vantage-answered.txt"), ""),
        )
        .on(
            "rustic",
            "",
            out(0, include_str!("answers/rustic-fin-01.json"), ""),
        )
        .on(
            "machinectl",
            "dl-01 --property=Leader",
            out(0, "4242\n", ""),
        )
        .on("nsenter", "-t 4242 -n", login)
}

/// Exit code and everything the run printed.
fn run(cfg: &Config, fake: &Fake) -> (i32, String) {
    let now = signoff::time::parse_rfc3339("2026-09-23T10:00:00+02:00").unwrap();
    let mut buf = Vec::new();
    let code = app::check(
        fake,
        cfg,
        &[cfg.service("qbittorrent").unwrap()],
        now,
        &mut buf,
    );
    (code, String::from_utf8(buf).unwrap())
}

fn factory_login_line(text: &str) -> &str {
    text.lines()
        .find(|l| l.contains("factory-login"))
        .unwrap_or_else(|| panic!("no factory-login line in:\n{text}"))
}

/// Without a declaration nothing changes: a hint, exit 0.
#[test]
fn b143_undeclared_stays_a_hint_by_default() {
    let cfg = parse(&toml("", "")).unwrap();
    let (code, text) = run(&cfg, &host(out(0, "401", "")));
    assert_eq!(code, 0, "{text}");
    assert_eq!(
        factory_login_line(&text),
        "qbittorrent     factory-login   undeclared       no probe in lib/werkskonten.nix"
    );
    assert!(
        text.ends_with("2 ok, 0 failed, 4 n/a, 1 undeclared, 0 cannot measure\n"),
        "{text}"
    );
}

/// Extension 1 — The exception with a reason: `n/a: <reason>`, exit 0, nothing tried.
#[test]
fn b143_exception_is_not_applicable_with_its_reason() {
    let cfg = parse(&toml(
        "",
        "no_factory_login = \"local login is disabled, OIDC only\"",
    ))
    .unwrap();
    let fake = host(out(0, "401", ""));
    let (code, text) = run(&cfg, &fake);
    assert_eq!(code, 0, "{text}");
    assert_eq!(
        factory_login_line(&text),
        "qbittorrent     factory-login   n/a              local login is disabled, OIDC only"
    );
    assert!(
        text.ends_with("2 ok, 0 failed, 5 n/a, 0 undeclared, 0 cannot measure\n"),
        "{text}"
    );
    assert!(
        fake.calls().iter().all(|(p, _, _)| p != "nsenter"),
        "an exception must not try the door"
    );
    // … and strict mode has nothing to object to: it IS declared.
    let cfg = parse(&toml(
        "undeclared_is_failure = true",
        "no_factory_login = \"local login is disabled, OIDC only\"",
    ))
    .unwrap();
    assert_eq!(run(&cfg, &host(out(0, "401", ""))).0, 0);
}

/// Extension 1 — An exception next to a probe, or one without a reason, is a
/// configuration error — not a run.
#[test]
fn b143_exception_with_a_probe_or_without_a_reason_is_a_config_error() {
    let e = parse(&toml(
        "",
        &format!("no_factory_login = \"no account\"\n{PROBE}"),
    ))
    .unwrap_err();
    assert_eq!(
        e,
        "config: service \"qbittorrent\": no_factory_login and factory_login are both declared — a service has a probe or a reason, not both"
    );
    for empty in ["", " ", " \\t "] {
        let e = parse(&toml("", &format!("no_factory_login = \"{empty}\""))).unwrap_err();
        assert_eq!(
            e,
            "config: service \"qbittorrent\": no_factory_login needs a reason, not an empty string"
        );
    }
}

/// Extension 2 — HTTP 200 with the rejection text: rejected.
#[test]
fn b143_reject_body_found_is_ok() {
    let cfg = parse(&toml("", PROBE)).unwrap();
    let fake = host(out(0, "Fails.\n200", ""));
    let (code, text) = run(&cfg, &fake);
    assert_eq!(code, 0, "{text}");
    assert_eq!(
        factory_login_line(&text),
        "qbittorrent     factory-login   ok               HTTP 200 with the expected rejection text: factory account rejected"
    );
    // The body is read under the narrow cap for what a guest answers, and
    // curl is asked for it (no `output = /dev/null`).
    let calls = fake.calls();
    let n = calls.iter().position(|(p, _, _)| p == "nsenter").unwrap();
    assert_eq!(fake.limits()[n], Limits::GUEST);
    let rc = String::from_utf8_lossy(calls[n].2.as_deref().unwrap()).into_owned();
    assert!(!rc.contains("/dev/null"), "{rc}");
    assert!(rc.contains("write-out = \"\\n%{http_code}\"\n"), "{rc}");
}

/// Extension 2 — The status is in `reject`, the text is missing: the door may be open.
/// The body (here: what an accepted login hands out) is not in the report.
#[test]
fn b143_reject_status_without_the_text_is_failed_and_the_body_stays_out() {
    let cfg = parse(&toml("", PROBE)).unwrap();
    let body = "Ok. SID=s3cr3t-session-token";
    let (code, text) = run(&cfg, &host(out(0, &format!("{body}\n200"), "")));
    assert_eq!(code, 1, "{text}");
    assert_eq!(
        factory_login_line(&text),
        "qbittorrent     factory-login   failed           HTTP 200, but the body (28 bytes) lacks the expected rejection text — the door may be open"
    );
    assert!(!text.contains("s3cr3t"), "{text}");
    assert!(!text.contains("SID="), "{text}");
    assert!(
        text.ends_with("2 ok, 1 failed, 4 n/a, 0 undeclared, 0 cannot measure\n"),
        "{text}"
    );
}

/// Extension 3 — Strict: neither a probe nor an exception is a finding, exit 1.
#[test]
fn b143_strict_makes_undeclared_a_failure() {
    let cfg = parse(&toml("undeclared_is_failure = true", "")).unwrap();
    let (code, text) = run(&cfg, &host(out(0, "401", "")));
    assert_eq!(code, 1, "{text}");
    assert_eq!(
        factory_login_line(&text),
        "qbittorrent     factory-login   failed           neither a factory_login probe nor a no_factory_login reason is declared (undeclared_is_failure)"
    );
    assert!(
        text.ends_with("2 ok, 1 failed, 4 n/a, 0 undeclared, 0 cannot measure\n"),
        "{text}"
    );
}

/// `plan` says the same as `check` would, without running anything.
#[test]
fn b143_plan_names_exception_body_and_strict() {
    let plan = |cfg: &Config| {
        let mut buf = Vec::new();
        app::plan(cfg, &[cfg.service("qbittorrent").unwrap()], &mut buf);
        let text = String::from_utf8(buf).unwrap();
        factory_login_line(&text).to_string()
    };
    assert_eq!(
        plan(&parse(&toml("", "no_factory_login = \"no account at all\"")).unwrap()),
        "qbittorrent     factory-login   n/a              no account at all"
    );
    assert_eq!(
        plan(&parse(&toml("", PROBE)).unwrap()),
        "qbittorrent     factory-login   POST http://10.0.20.10:8080/api/v2/auth/login from the host's curl in the network of dl-01, reject [200] with a body containing \"Fails.\""
    );
    assert_eq!(
        plan(&parse(&toml("undeclared_is_failure = true", "")).unwrap()),
        "qbittorrent     factory-login   failed           neither a factory_login probe nor a no_factory_login reason is declared (undeclared_is_failure)"
    );
    assert_eq!(
        plan(&parse(&toml("", "")).unwrap()),
        "qbittorrent     factory-login   undeclared       no probe in lib/werkskonten.nix"
    );
}
