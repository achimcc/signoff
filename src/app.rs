//! Dispatch, the run over one or all services, the plan, the rules.

use crate::checks::{backend, backup, dns, factory_login, outpost, public_path};
use crate::cli::{Args, Cmd, USAGE};
use crate::config::{Config, Service};
use crate::runner::{Runner, System};
use crate::verdict::{Finding, Summary, Verdict, format_line};
use std::io::Write;

pub const RULES: &str = "\
signoff asks, per service, whether it is really done. Seven measurements:

  dns-a, dns-aaaa   dig @<resolver>: the name must resolve to the VPS (the zone
                    carries a wildcard, so \"some record\" proves nothing)
  public-path       curl --resolve <host>:443:<vps>: any HTTP status is ok — the
                    home proxy answered; curl exit 35 \"unrecognized name\" means the
                    VPS's default vhost refused: the name is not in the SNI map
  backend           vantage probe --from <proxy guest> <guest>:<port>: answered is
                    ok; refused / dropped at zone edge / dropped elsewhere are findings
  outpost           a proxy provider with external_host https://<host> exists and the
                    embedded outpost carries it (only with forward_auth)
  backup            the newest rustic snapshot for the guest's dataset is younger
                    than snapshot_max_age_hours
  factory-login     the declared vendor default account is rejected (tried inside
                    the guest, against the backend); no declaration → undeclared

Verdicts:
  ok               measured, as expected
  failed           measured, not as expected — a finding (exit 1)
  cannot measure   the path to the answer did not carry (exit 2)
  n/a: <why>       not applicable to this service (not public, no backend,
                   no forward_auth) — never changes the exit code
  undeclared       factory-login only: nobody declared a probe — a hint, not green

Controls, once per run, before any measurement (exit 2 if one fails):
  the resolver answers SOA for the zone; an invented name is refused by the
  VPS (else a 200 proves nothing); the backup repository lists snapshots at all.
";

pub fn main(argv: &[String]) -> i32 {
    let args: Args = match crate::cli::parse(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("signoff: {e}\n\n{USAGE}");
            return 2;
        }
    };
    let is_plan = matches!(args.cmd, Cmd::Plan { .. });
    match args.cmd {
        Cmd::Help => {
            println!("{USAGE}");
            0
        }
        Cmd::Version => {
            println!("signoff {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Cmd::Rules => {
            print!("{RULES}");
            0
        }
        Cmd::Check { services, all } | Cmd::Plan { services, all } => {
            let cfg = match crate::config::load(&args.config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("signoff: {e}");
                    return 2;
                }
            };
            let selected: Vec<&Service> = if all {
                cfg.service.iter().collect()
            } else {
                let mut v = Vec::new();
                for key in &services {
                    match cfg.service(key) {
                        Some(s) => v.push(s),
                        None => {
                            eprintln!(
                                "signoff: no service {key:?} in {} (known: {})",
                                args.config.display(),
                                cfg.service
                                    .iter()
                                    .map(|s| s.key.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            );
                            return 2;
                        }
                    }
                }
                v
            };
            let mut out = std::io::stdout().lock();
            if is_plan {
                plan(&cfg, &selected, &mut out);
                0
            } else {
                check(&System, &cfg, &selected, crate::time::now(), &mut out)
            }
        }
    }
}

fn emit(out: &mut dyn Write, findings: &mut Vec<Finding>, f: Finding) {
    let _ = writeln!(out, "{}", format_line(&f));
    findings.push(f);
}

type Control = fn(&dyn Runner, &Config) -> Result<(), String>;

pub fn check(
    r: &dyn Runner,
    cfg: &Config,
    services: &[&Service],
    now: i64,
    out: &mut dyn Write,
) -> i32 {
    // Function pointers, not called results: an array of the RESULTS would
    // evaluate (and run) all three controls before the loop ever looks at
    // the first one. This way the loop stops after the first failure and
    // never touches the network for the remaining controls.
    let controls: [Control; 3] = [
        dns::control_soa,
        public_path::control_canary,
        backup::control_repo,
    ];
    for control in controls {
        if let Err(e) = control(r, cfg) {
            eprintln!("signoff: control failed: {e}");
            return 2;
        }
    }
    let mut auth: Option<Result<outpost::Auth, String>> = None;
    let mut findings = Vec::new();
    for s in services {
        let key = s.key.clone();
        let line = |check: &'static str, v: Verdict| Finding {
            service: key.clone(),
            check,
            verdict: v,
        };
        emit(out, &mut findings, line("dns-a", dns::check_a(r, cfg, s)));
        emit(
            out,
            &mut findings,
            line("dns-aaaa", dns::check_aaaa(r, cfg, s)),
        );
        emit(
            out,
            &mut findings,
            line("public-path", public_path::check(r, cfg, s)),
        );
        emit(
            out,
            &mut findings,
            line("backend", backend::check(r, cfg, s)),
        );
        let outpost_verdict = if !s.forward_auth {
            Verdict::NotApplicable("no forward_auth".into())
        } else {
            let a = auth.get_or_insert_with(|| outpost::Auth::fetch(r, cfg));
            match a {
                Ok(a) => outpost::check(r, cfg, s, a),
                Err(e) => Verdict::CannotMeasure(e.clone()),
            }
        };
        emit(out, &mut findings, line("outpost", outpost_verdict));
        emit(
            out,
            &mut findings,
            line("backup", backup::check(r, cfg, s, now)),
        );
        emit(
            out,
            &mut findings,
            line("factory-login", factory_login::check(r, s)),
        );
    }
    let summary = Summary::of(&findings);
    let _ = writeln!(out, "{}", summary.line());
    summary.exit_code()
}

pub fn plan(cfg: &Config, services: &[&Service], out: &mut dyn Write) {
    let row = |out: &mut dyn Write, s: &Service, check: &str, what: String| {
        let _ = writeln!(out, "{:<15} {:<15} {}", s.key, check, what);
    };
    let na = |why: &str| format!("{:<16} {why}", "n/a");
    for s in services {
        if s.public {
            row(
                out,
                s,
                "dns-a",
                format!("dig {}", dns::args(&cfg.resolver, "A", &s.host).join(" ")),
            );
            row(
                out,
                s,
                "dns-aaaa",
                format!(
                    "dig {}",
                    dns::args(&cfg.resolver, "AAAA", &s.host).join(" ")
                ),
            );
            row(
                out,
                s,
                "public-path",
                format!(
                    "curl … --resolve {}:443:{} https://{}/",
                    s.host, cfg.vps_v4, s.host
                ),
            );
        } else {
            for c in ["dns-a", "dns-aaaa", "public-path"] {
                row(out, s, c, na("not public"));
            }
        }
        match (&s.backend_guest, s.backend_port()) {
            (Some(g), Some(p)) => row(
                out,
                s,
                "backend",
                format!(
                    "vantage {}",
                    backend::args(&cfg.caddy_guest, g, p).join(" ")
                ),
            ),
            _ => row(out, s, "backend", na("no backend")),
        }
        if s.forward_auth {
            row(
                out,
                s,
                "outpost",
                format!(
                    "GET {}/providers/proxy/ and /outposts/instances/ in {}: external_host https://{} attached to \"{}\"",
                    cfg.auth_api, cfg.auth_guest, s.host, cfg.outpost
                ),
            );
        } else {
            row(out, s, "outpost", na("no forward_auth"));
        }
        row(
            out,
            s,
            "backup",
            format!(
                "rustic {} (newest younger than {} h)",
                backup::args(&cfg.rustic_profile, Some(&s.dataset)).join(" "),
                cfg.snapshot_max_age_hours
            ),
        );
        match (&s.factory_login, &s.backend) {
            (Some(f), Some(b)) => row(
                out,
                s,
                "factory-login",
                format!(
                    "{} http://{b}{} in {}, reject {:?}",
                    f.method, f.path, s.guest, f.reject
                ),
            ),
            (Some(_), None) => row(
                out,
                s,
                "factory-login",
                format!(
                    "{:<16} factory_login declared but no backend",
                    "cannot measure"
                ),
            ),
            (None, _) => row(
                out,
                s,
                "factory-login",
                format!("{:<16} no probe in lib/werkskonten.nix", "undeclared"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;
    use crate::runner::{Fake, Output};
    use crate::time::parse_rfc3339;

    fn out(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }
    fn cfg() -> Config {
        parse(include_str!("../tests/answers/signoff.toml")).unwrap()
    }
    fn noon() -> i64 {
        parse_rfc3339("2026-09-23T10:00:00+02:00").unwrap()
    }
    /// A host where everything is in order.
    fn healthy() -> Fake {
        Fake::new()
            .on(
                "dig",
                "SOA rusty-vault.de",
                out(0, "ns. hostmaster. 1 2 3 4 5\n", ""),
            )
            .on("dig", "AAAA", out(0, "2a01:4f9:c013:5ee7::1\n", ""))
            .on("dig", " A ", out(0, "77.42.71.141\n", ""))
            .on(
                "curl",
                "signoff-canary-",
                out(
                    35,
                    "000",
                    include_str!("../tests/answers/curl-35-unrecognized.txt"),
                ),
            )
            .on("curl", "https://", out(0, "302", ""))
            .on(
                "vantage",
                "probe",
                out(0, include_str!("../tests/answers/vantage-answered.txt"), ""),
            )
            .on("systemd-run", "authentik-kurztoken", out(0, "tok\n", ""))
            .on(
                "systemd-run",
                "providers/proxy",
                out(
                    0,
                    include_str!("../tests/answers/authentik-providers.json"),
                    "",
                ),
            )
            .on(
                "systemd-run",
                "outposts/instances",
                out(
                    0,
                    include_str!("../tests/answers/authentik-outposts.json"),
                    "",
                ),
            )
            .on("systemd-run", "--machine=fin-01", out(0, "401", ""))
            .on(
                "rustic",
                "--filter-label",
                out(0, include_str!("../tests/answers/rustic-fin-01.json"), ""),
            )
            .on(
                "rustic",
                "snapshots --json",
                out(0, include_str!("../tests/answers/rustic-fin-01.json"), ""),
            )
    }

    #[test]
    fn a_healthy_service_prints_seven_lines_and_exits_zero() {
        let c = cfg();
        let mut buf = Vec::new();
        let code = check(
            &healthy(),
            &c,
            &[c.service("ghostfolio").unwrap()],
            noon(),
            &mut buf,
        );
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(code, 0, "{text}");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 8, "{text}");
        for (i, check) in [
            "dns-a",
            "dns-aaaa",
            "public-path",
            "backend",
            "outpost",
            "backup",
            "factory-login",
        ]
        .iter()
        .enumerate()
        {
            assert!(lines[i].starts_with("ghostfolio"), "{}", lines[i]);
            assert!(lines[i].contains(check), "{}", lines[i]);
            assert!(lines[i].contains(" ok "), "{}", lines[i]);
        }
        assert_eq!(
            lines[7],
            "7 ok, 0 failed, 0 n/a, 0 undeclared, 0 cannot measure"
        );
    }

    #[test]
    fn internal_service_without_forward_auth_has_na_lines_and_no_token_fetch() {
        let c = cfg();
        let fake = healthy();
        let mut buf = Vec::new();
        let code = check(&fake, &c, &[c.service("radarr").unwrap()], noon(), &mut buf);
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(code, 0, "{text}");
        assert!(
            text.contains("dns-a           n/a              not public"),
            "{text}"
        );
        assert!(
            text.contains("outpost         n/a              no forward_auth"),
            "{text}"
        );
        assert!(text.contains("factory-login   undeclared"), "{text}");
        assert!(
            !fake
                .calls()
                .iter()
                .any(|(_, a, _)| a.join(" ").contains("authentik-kurztoken"))
        );
    }

    #[test]
    fn token_is_fetched_once_for_all_services() {
        let c = cfg();
        let fake = healthy();
        let all: Vec<&crate::config::Service> = c.service.iter().collect();
        let mut buf = Vec::new();
        check(&fake, &c, &all, noon(), &mut buf);
        let fetches = fake
            .calls()
            .iter()
            .filter(|(_, a, _)| a.join(" ").contains("authentik-kurztoken"))
            .count();
        assert_eq!(fetches, 1);
    }

    #[test]
    fn a_failed_control_stops_before_any_measurement_with_exit_two() {
        let c = cfg();
        let fake = Fake::new().on("dig", "SOA", out(9, "", ""));
        let mut buf = Vec::new();
        let code = check(
            &fake,
            &c,
            &[c.service("ghostfolio").unwrap()],
            noon(),
            &mut buf,
        );
        assert_eq!(code, 2);
        assert!(String::from_utf8(buf).unwrap().is_empty());
        assert_eq!(fake.calls().len(), 1);
    }

    /// Rules are matched first-wins, so the failing vantage answer goes in
    /// front of everything `healthy()` would have said.
    fn with_dropped_backend() -> Fake {
        let mut f = Fake::new().on(
            "vantage",
            "probe",
            out(1, include_str!("../tests/answers/vantage-edge.txt"), ""),
        );
        f = f
            .on(
                "dig",
                "SOA rusty-vault.de",
                out(0, "ns. hostmaster. 1 2 3 4 5\n", ""),
            )
            .on("dig", "AAAA", out(0, "2a01:4f9:c013:5ee7::1\n", ""))
            .on("dig", " A ", out(0, "77.42.71.141\n", ""))
            .on(
                "curl",
                "signoff-canary-",
                out(
                    35,
                    "000",
                    include_str!("../tests/answers/curl-35-unrecognized.txt"),
                ),
            )
            .on("curl", "https://", out(0, "302", ""))
            .on("systemd-run", "authentik-kurztoken", out(0, "tok\n", ""))
            .on(
                "systemd-run",
                "providers/proxy",
                out(
                    0,
                    include_str!("../tests/answers/authentik-providers.json"),
                    "",
                ),
            )
            .on(
                "systemd-run",
                "outposts/instances",
                out(
                    0,
                    include_str!("../tests/answers/authentik-outposts.json"),
                    "",
                ),
            )
            .on("systemd-run", "--machine=fin-01", out(0, "401", ""))
            .on(
                "rustic",
                "",
                out(0, include_str!("../tests/answers/rustic-fin-01.json"), ""),
            );
        f
    }

    #[test]
    fn one_finding_makes_exit_one_and_names_it() {
        let c = cfg();
        let mut buf = Vec::new();
        let code = check(
            &with_dropped_backend(),
            &c,
            &[c.service("ghostfolio").unwrap()],
            noon(),
            &mut buf,
        );
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(code, 1, "{text}");
        assert!(
            text.contains("backend         failed           dropped at zone edge"),
            "{text}"
        );
        assert!(
            text.ends_with("6 ok, 1 failed, 0 n/a, 0 undeclared, 0 cannot measure\n"),
            "{text}"
        );
    }

    #[test]
    fn plan_lists_commands_without_running_anything() {
        let c = cfg();
        let mut buf = Vec::new();
        plan(
            &c,
            &[
                c.service("ghostfolio").unwrap(),
                c.service("start").unwrap(),
            ],
            &mut buf,
        );
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("dig +short +time=3 +tries=1 A ghostfolio.rusty-vault.de @1.1.1.1"),
            "{text}"
        );
        assert!(text.contains("curl … --resolve ghostfolio.rusty-vault.de:443:77.42.71.141 https://ghostfolio.rusty-vault.de/"), "{text}");
        assert!(
            text.contains("vantage probe --from infra-01 fin-01:3333"),
            "{text}"
        );
        assert!(
            text.contains(
                "rustic -P /etc/rustic/rustic snapshots --json --filter-label rpool/guests/fin-01"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "POST http://10.0.190.10:3333/api/auth/token in fin-01, reject [401, 403]"
            ),
            "{text}"
        );
        assert!(
            text.contains("start           backend         n/a              no backend"),
            "{text}"
        );
    }

    #[test]
    fn main_reports_an_unknown_service_and_a_missing_config() {
        // No config file at this path: exit 2 with the path in the message.
        assert_eq!(
            main(&[
                "--config".into(),
                "/nonexistent/signoff.toml".into(),
                "check".into(),
                "--all".into()
            ]),
            2
        );
        assert_eq!(main(&["rules".into()]), 0);
        assert_eq!(main(&["--version".into()]), 0);
        assert_eq!(main(&["bogus".into()]), 2);
    }
}
