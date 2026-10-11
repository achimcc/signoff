//! Does the name resolve, from outside, to where it must? The zone carries a
//! wildcard, so "any record" proves nothing — the answer must BE the
//! expected address: the VPS, or (`dns_a`/`dns_aaaa = "home"`, since 0.4.0)
//! the home connection.
//!
//! THE HOME ADDRESS NEVER APPEARS IN A LINE. The report goes to the journal,
//! the journal to Loki, and the home connection's address is not to be kept
//! there (the host's `hausadresse.nix` keeps it in a file for that reason).
//! A home verdict says "home address", a finding says whether the record
//! points to the VPS or merely elsewhere — a foreign address found in place
//! of the home one could be an OLD home address, so it is withheld as well.

use crate::config::{Config, Service, Target};
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
        .filter(|l| l.parse::<std::net::IpAddr>().is_ok())
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

fn addresses(out: &Output) -> Vec<std::net::IpAddr> {
    out.stdout
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

/// Like `judge`, against the home address — and without ever printing it.
/// `vps` is named in a finding: it is public, and "points to the VPS" is
/// the one wrong answer that says what to do (the updater does not own the
/// name, or the zone tool wrote it back).
pub fn judge_home(out: &Output, rrtype: &str, home: &str, source: &str, vps: &str) -> Verdict {
    if out.code != Some(0) {
        return Verdict::CannotMeasure(format!("dig exit {:?}", out.code));
    }
    let (Ok(home), Ok(vps_ip)) = (
        home.parse::<std::net::IpAddr>(),
        vps.parse::<std::net::IpAddr>(),
    ) else {
        return Verdict::CannotMeasure("home or VPS address does not parse".into());
    };
    let found = addresses(out);
    if found.contains(&home) {
        return Verdict::Ok(format!("home address ({source})"));
    }
    match found.first() {
        None => Verdict::Failed(format!("no {rrtype} record")),
        Some(a) if *a == vps_ip => Verdict::Failed(format!(
            "{rrtype} points to the VPS ({vps}), expected the home address ({source}) — is the name in ddclient's domains?"
        )),
        Some(_) => Verdict::Failed(format!(
            "{rrtype} differs from the home address ({source}); address withheld — wildcard, Cloudflare proxy or a stale record?"
        )),
    }
}

/// The soll for `dns_a = "home"`: the file the host keeps current from the
/// outside view. Neither its content nor a parse error quotes the value.
pub fn home_v4(path: &str, vps_v4: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let ip: std::net::Ipv4Addr = text
        .trim()
        .parse()
        .map_err(|_| format!("{path} does not hold one IPv4 address"))?;
    if ip.to_string() == vps_v4 {
        return Err(format!("{path} holds the VPS address, not a home address"));
    }
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
        return Err(format!("{path} holds a non-public address"));
    }
    Ok(ip.to_string())
}

/// Label of a name the zone does not carry: its answer is the wildcard's.
pub const WILDCARD_PROBE: &str = "signoff-wildcard-probe";

/// The soll for `dns_aaaa = "home"`: the AAAA of a reference name.
///
/// WHY A REFERENCE NAME AND NOT A FILE OR THE HOST'S OWN ADDRESS: The home
/// AAAA is written by ddclient from ITS outside view (`webv6`, in the proxy
/// guest behind NAT66). There is no file like the v4 one, and the host's
/// own interface address need not be the one the outside sees. The
/// reference (`nur6.<zone>` on the host) is written by the same updater,
/// from the same lookup, in the same run — so a home name agrees with it
/// exactly when the updater owns the name too. What this catches is what
/// broke before: a name the updater does not own (VPS address written back
/// by the zone tool), a missing record (the wildcard answers) and a proxied
/// one.
///
/// AND WHY IT CAN STILL TURN RED: A reference that is itself broken would
/// make every comparison meaningless, so it is checked first — exactly one
/// AAAA, not the VPS, and not the wildcard's answer (a missing reference
/// record answers like the wildcard, and so would every missing home
/// record: equal, and wrongly green). The wildcard is asked, not a fixed
/// list of Cloudflare ranges: the list would go stale, the question cannot.
/// Not caught: the updater writing a wrong address everywhere at once —
/// that is ddclient's failure, visible on the public path, not in the zone.
pub fn home_v6(r: &dyn Runner, cfg: &Config, reference: &str) -> Result<String, String> {
    let ask = |name: &str| -> Result<Vec<std::net::IpAddr>, String> {
        let out = r.run(DIG, &args(&cfg.resolver, "AAAA", name), None)?;
        if out.code != Some(0) {
            return Err(format!("dig AAAA {name}: exit {:?}", out.code));
        }
        Ok(addresses(&out))
    };
    let found = ask(reference)?;
    let [soll] = found.as_slice() else {
        return Err(format!(
            "reference {reference}: expected exactly one AAAA, got {}",
            found.len()
        ));
    };
    if cfg.vps_v6.parse::<std::net::IpAddr>().ok() == Some(*soll) {
        return Err(format!(
            "reference {reference} points to the VPS — it is not the home address"
        ));
    }
    let wildcard = ask(&format!("{WILDCARD_PROBE}.{}", cfg.zone))?;
    if wildcard.contains(soll) {
        return Err(format!(
            "reference {reference} answers like the wildcard — its own record is missing"
        ));
    }
    Ok(soll.to_string())
}

/// The home sollwerte of one run, fetched once and only when a service
/// needs them. `None`: nobody asked.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Home {
    pub v4: Option<Result<String, String>>,
    pub v6: Option<Result<String, String>>,
}

impl Home {
    pub fn fetch(r: &dyn Runner, cfg: &Config, services: &[&Service]) -> Home {
        let needs =
            |f: fn(&Service) -> Target| services.iter().any(|s| s.public && f(s) == Target::Home);
        let missing = |field: &str| Err(format!("{field} is not configured"));
        Home {
            v4: needs(|s| s.dns_a).then(|| match &cfg.home_v4_file {
                Some(p) => home_v4(p, &cfg.vps_v4),
                None => missing("home_v4_file"),
            }),
            v6: needs(|s| s.dns_aaaa).then(|| match &cfg.home_v6_reference {
                Some(n) => home_v6(r, cfg, n),
                None => missing("home_v6_reference"),
            }),
        }
    }
}

struct Family<'a> {
    rrtype: &'a str,
    target: Target,
    vps: &'a str,
    home: Option<&'a Result<String, String>>,
    source: &'a str,
}

fn check(r: &dyn Runner, cfg: &Config, s: &Service, f: Family) -> Verdict {
    if !s.public {
        return Verdict::NotApplicable("not public".into());
    }
    let home = match (f.target, f.home) {
        (Target::Vps, _) => None,
        (Target::Home, Some(Ok(a))) => Some(a),
        (Target::Home, Some(Err(e))) => {
            return Verdict::CannotMeasure(format!("home address: {e}"));
        }
        (Target::Home, None) => {
            return Verdict::CannotMeasure("home address was not fetched".into());
        }
    };
    match r.run(DIG, &args(&cfg.resolver, f.rrtype, &s.host), None) {
        Ok(out) => match home {
            None => judge(&out, f.rrtype, f.vps),
            Some(h) => judge_home(&out, f.rrtype, h, f.source, f.vps),
        },
        Err(e) => Verdict::CannotMeasure(e),
    }
}

pub fn check_a(r: &dyn Runner, cfg: &Config, s: &Service, home: &Home) -> Verdict {
    let source = cfg.home_v4_file.as_deref().unwrap_or("home_v4_file");
    check(
        r,
        cfg,
        s,
        Family {
            rrtype: "A",
            target: s.dns_a,
            vps: &cfg.vps_v4,
            home: home.v4.as_ref(),
            source,
        },
    )
}

pub fn check_aaaa(r: &dyn Runner, cfg: &Config, s: &Service, home: &Home) -> Verdict {
    let source = cfg
        .home_v6_reference
        .as_deref()
        .map(|n| format!("AAAA of {n}"))
        .unwrap_or_else(|| "home_v6_reference".into());
    check(
        r,
        cfg,
        s,
        Family {
            rrtype: "AAAA",
            target: s.dns_aaaa,
            vps: &cfg.vps_v6,
            home: home.v6.as_ref(),
            source: &source,
        },
    )
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
            judge(
                &out(include_str!("../../tests/answers/dig-empty.txt"), 0),
                "AAAA",
                "2a01::1"
            ),
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
    fn hex_hostname_is_not_an_address() {
        let v = judge(
            &out("abcd.badface.de.\n77.42.71.141\n", 0),
            "A",
            "77.42.71.141",
        );
        assert_eq!(v, Verdict::Ok("77.42.71.141".into()));
        let v = judge(&out("abcd.badface.de.\n", 0), "A", "77.42.71.141");
        assert_eq!(v, Verdict::Failed("no A record".into()));
    }

    #[test]
    fn internal_service_is_not_applicable() {
        let c = cfg();
        let fake = Fake::new();
        assert_eq!(
            check_a(&fake, &c, c.service("radarr").unwrap(), &Home::default()),
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
        assert_eq!(
            check_a(&fake, &c, s, &Home::default()),
            Verdict::Ok("77.42.71.141".into())
        );
        assert_eq!(
            check_aaaa(&fake, &c, s, &Home::default()),
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

    // --- Ziel "home" (0.4.0): die Faelle vom 2026-10-11 nachgebaut --------
    //
    // An dem Morgen zeigten 31 oeffentliche Namen auf den Anschluss
    // (ddclient), signoff erwartete den VPS und meldete 31x dns-a und 31x
    // dns-aaaa als Befund. Adressen hier aus den Dokumentationsbereichen.

    const HOME_V4: &str = "198.51.100.7";
    const HOME_V6: &str = "2001:db8:1::10";
    const CF_V6: &str = "2606:4700:3030::6815:2001";

    /// Die Beispielkonfiguration mit ghostfolio auf "home" und einer
    /// Adressdatei mit `inhalt` (je Test eine eigene Datei).
    fn home_cfg(test: &str, inhalt: &str) -> Config {
        let pfad =
            std::env::temp_dir().join(format!("signoff-test-{}-{test}-v4", std::process::id()));
        std::fs::write(&pfad, inhalt).unwrap();
        let ghostfolio = "dataset = \"rpool/guests/fin-01\"\n";
        let t = include_str!("../../tests/answers/signoff.toml").replace(
            ghostfolio,
            &format!("{ghostfolio}dns_a = \"home\"\ndns_aaaa = \"home\"\n"),
        );
        parse(&format!(
            "home_v4_file = {:?}\nhome_v6_reference = \"nur6.rusty-vault.de\"\n{t}",
            pfad.to_str().unwrap()
        ))
        .unwrap()
    }

    /// nur6 traegt die Hausadresse, der Wildcard antwortet mit Cloudflare.
    fn zone_mit_referenz(first: Fake) -> Fake {
        first
            .on(
                "dig",
                "AAAA nur6.rusty-vault.de",
                out(&format!("{HOME_V6}\n"), 0),
            )
            .on(
                "dig",
                "AAAA signoff-wildcard-probe.rusty-vault.de",
                out(&format!("{CF_V6}\n"), 0),
            )
    }

    fn ghost(c: &Config) -> &Service {
        c.service("ghostfolio").unwrap()
    }

    #[test]
    fn home_a_from_the_file_is_ok_and_never_names_the_address() {
        let c = home_cfg("a-ok", &format!("{HOME_V4}\n"));
        let fake = zone_mit_referenz(Fake::new()).on(
            "dig",
            "A ghostfolio.rusty-vault.de",
            out(&format!("{HOME_V4}\n"), 0),
        );
        let home = Home::fetch(&fake, &c, &[ghost(&c)]);
        let v = check_a(&fake, &c, ghost(&c), &home);
        assert!(
            matches!(&v, Verdict::Ok(d) if d.starts_with("home address")),
            "{v:?}"
        );
        assert!(!format!("{v:?}").contains(HOME_V4));
    }

    #[test]
    fn home_a_pointing_to_the_vps_is_a_finding() {
        let c = home_cfg("a-vps", HOME_V4);
        let fake =
            zone_mit_referenz(Fake::new()).on("dig", "A ghostfolio", out("77.42.71.141\n", 0));
        let home = Home::fetch(&fake, &c, &[ghost(&c)]);
        let v = check_a(&fake, &c, ghost(&c), &home);
        let Verdict::Failed(d) = &v else {
            panic!("{v:?}")
        };
        assert!(d.contains("points to the VPS (77.42.71.141)"), "{d}");
        assert!(!d.contains(HOME_V4), "{d}");
    }

    #[test]
    fn home_a_pointing_to_cloudflare_or_an_old_address_is_withheld() {
        let c = home_cfg("a-cf", HOME_V4);
        for gefunden in ["104.21.32.1", "203.0.113.99"] {
            let fake = zone_mit_referenz(Fake::new()).on(
                "dig",
                "A ghostfolio",
                out(&format!("{gefunden}\n"), 0),
            );
            let home = Home::fetch(&fake, &c, &[ghost(&c)]);
            let v = check_a(&fake, &c, ghost(&c), &home);
            let Verdict::Failed(d) = &v else {
                panic!("{v:?}")
            };
            assert!(d.contains("differs from the home address"), "{d}");
            assert!(!d.contains(gefunden) && !d.contains(HOME_V4), "{d}");
        }
    }

    #[test]
    fn home_aaaa_equal_to_the_reference_is_ok_vps_and_wildcard_are_findings() {
        let c = home_cfg("aaaa", HOME_V4);
        let mit = |antwort: &str| {
            zone_mit_referenz(Fake::new()).on(
                "dig",
                "AAAA ghostfolio",
                out(&format!("{antwort}\n"), 0),
            )
        };
        let fake = mit(HOME_V6);
        let home = Home::fetch(&fake, &c, &[ghost(&c)]);
        assert_eq!(
            check_aaaa(&fake, &c, ghost(&c), &home),
            Verdict::Ok("home address (AAAA of nur6.rusty-vault.de)".into())
        );
        let fake = mit("2a01:4f9:c013:5ee7::1");
        let v = check_aaaa(&fake, &c, ghost(&c), &home);
        assert!(
            matches!(&v, Verdict::Failed(d) if d.contains("points to the VPS")),
            "{v:?}"
        );
        let fake = mit(CF_V6);
        let v = check_aaaa(&fake, &c, ghost(&c), &home);
        assert!(
            matches!(&v, Verdict::Failed(d) if d.contains("differs") && !d.contains(HOME_V6)),
            "{v:?}"
        );
    }

    #[test]
    fn a_broken_reference_is_cannot_measure_not_green() {
        let c = home_cfg("ref", HOME_V4);
        // Der Referenzname fehlt: er antwortet wie der Wildcard - und ein
        // fehlender Dienstname taete es auch. Gleich, aber nicht gruen.
        let wie_wildcard = Fake::new()
            .on(
                "dig",
                "AAAA nur6.rusty-vault.de",
                out(&format!("{CF_V6}\n"), 0),
            )
            .on(
                "dig",
                "AAAA signoff-wildcard-probe",
                out(&format!("{CF_V6}\n"), 0),
            )
            .on("dig", "AAAA ghostfolio", out(&format!("{CF_V6}\n"), 0));
        let home = Home::fetch(&wie_wildcard, &c, &[ghost(&c)]);
        let v = check_aaaa(&wie_wildcard, &c, ghost(&c), &home);
        assert!(
            matches!(&v, Verdict::CannotMeasure(d) if d.contains("wildcard")),
            "{v:?}"
        );

        let auf_vps = Fake::new().on(
            "dig",
            "AAAA nur6.rusty-vault.de",
            out("2a01:4f9:c013:5ee7::1\n", 0),
        );
        let e = home_v6(&auf_vps, &c, "nur6.rusty-vault.de").unwrap_err();
        assert!(e.contains("VPS"), "{e}");

        let zwei = Fake::new().on(
            "dig",
            "AAAA nur6.rusty-vault.de",
            out("2001:db8:1::10\n2001:db8:1::11\n", 0),
        );
        let e = home_v6(&zwei, &c, "nur6.rusty-vault.de").unwrap_err();
        assert!(e.contains("exactly one"), "{e}");
    }

    #[test]
    fn a_broken_home_file_is_cannot_measure_and_never_quoted() {
        for (test, inhalt) in [
            ("leer", ""),
            ("kaputt", "<html>secret-ish</html>"),
            ("vps", "77.42.71.141\n"),
            ("privat", "192.168.20.1\n"),
        ] {
            let c = home_cfg(test, inhalt);
            let fake = zone_mit_referenz(Fake::new()).on(
                "dig",
                "A ghostfolio",
                out(&format!("{HOME_V4}\n"), 0),
            );
            let home = Home::fetch(&fake, &c, &[ghost(&c)]);
            let v = check_a(&fake, &c, ghost(&c), &home);
            let Verdict::CannotMeasure(d) = &v else {
                panic!("{test}: {v:?}")
            };
            assert!(!d.contains("secret-ish") && !d.contains("192.168"), "{d}");
        }
        let fehlt = home_v4("/nonexistent/signoff/v4", "77.42.71.141").unwrap_err();
        assert!(fehlt.contains("/nonexistent/signoff/v4"), "{fehlt}");
    }

    #[test]
    fn home_is_fetched_only_when_a_public_service_needs_it() {
        let c = cfg();
        let fake = Fake::new();
        let alle: Vec<&Service> = c.service.iter().collect();
        assert_eq!(Home::fetch(&fake, &c, &alle), Home::default());
        assert!(fake.calls().is_empty());
        // Ein "vps"-Dienst daneben bleibt beim alten Urteil.
        let c = home_cfg("vps-daneben", HOME_V4);
        let fake =
            zone_mit_referenz(Fake::new()).on("dig", "A rusty-vault.de", out("77.42.71.141\n", 0));
        let home = Home::fetch(&fake, &c, &[ghost(&c)]);
        assert_eq!(
            check_a(&fake, &c, c.service("start").unwrap(), &home),
            Verdict::Ok("77.42.71.141".into())
        );
    }
}
