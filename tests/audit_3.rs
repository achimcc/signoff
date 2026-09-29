//! Riegel aus Audit 3 (homeserver, 2026-09-27), Befunde B112 und B113.
//! Beide Faelle stammen aus dem Probetest des Auditors (`audit_a2.rs`) und
//! waren gegen v0.1.1 rot.

use signoff::checks::backup;
use signoff::checks::factory_login;
use signoff::config::parse;
use signoff::runner::{Fake, Limits, Output};
use signoff::verdict::{Finding, format_line};

fn out(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        code: Some(code),
        stdout: stdout.into(),
        stderr: stderr.into(),
    }
}

/// B112: Eine Gastausgabe mit Escape-Folgen (OSC 52 schreibt in die
/// Zwischenablage, `ESC [ 2 J` loescht den Schirm) und einem Zeilenumbruch
/// (eine erfundene zweite Berichtszeile) kommt nur SICHTBAR in den Bericht.
#[test]
fn b112_gastausgabe_kommt_nur_sichtbar_in_den_bericht() {
    let cfg = parse(include_str!("answers/signoff.toml")).unwrap();
    let s = cfg.service("ghostfolio").unwrap();
    let boese = "\x1b]52;c;ZWNobyBoaQ==\x07\x1b[2Jcurl: (7) x\u{202e}";
    // Jede Probe antwortet mit demselben Text — gleich, ueber welchen Weg
    // factory-login geht (Gast-curl oder Wirts-curl im Gast-Netz).
    let fake = Fake::new()
        .on("machinectl", "Leader", out(0, "4242\n", ""))
        .on("nsenter", "", out(7, "", boese))
        .on("systemd-run", "", out(7, "", boese));
    let zeile = format_line(&Finding {
        service: s.key.clone(),
        check: "factory-login",
        verdict: factory_login::check(&fake, s),
    });
    assert!(
        !zeile.chars().any(|c| c.is_control() || c == '\u{202e}'),
        "Steuerzeichen im Bericht: {zeile:?}"
    );
    assert!(zeile.contains("\\x1b]52;c;"), "{zeile:?}");
    assert!(zeile.contains("\\u{202e}"), "{zeile:?}");
}

/// B113: Die Werkskonto-Probe darf kein Programm des Gastes ausfuehren —
/// ein uebernommener Gast, dessen curl immer 401 sagt, bestimmte sonst das
/// Urteil. Sie laeuft mit dem curl des WIRTS im Netz-Namensraum des Gastes.
#[test]
fn b113_werkskonto_probe_faehrt_kein_gastprogramm() {
    let cfg = parse(include_str!("answers/signoff.toml")).unwrap();
    let s = cfg.service("ghostfolio").unwrap();
    let fake = Fake::new()
        // Der luegende Gast: jedes Programm in ihm sagt 401.
        .on("systemd-run", "", out(0, "401", ""))
        .on("machinectl", "Leader", out(0, "4242\n", ""))
        .on("nsenter", "", out(0, "200", ""));
    let v = factory_login::check(&fake, s);
    let aufrufe = fake.calls();
    // Nur Programm und argv in die Meldung — stdin traegt die Probe.
    let gezeigt: Vec<_> = aufrufe.iter().map(|(p, a, _)| (p, a)).collect();
    assert!(
        aufrufe.iter().all(|(p, _, _)| p != "systemd-run"),
        "Gastprogramm aufgerufen: {gezeigt:?}"
    );
    let (_, argv, stdin) = aufrufe
        .iter()
        .find(|(p, _, _)| p == "nsenter")
        .expect("kein nsenter-Aufruf");
    assert_eq!(argv, &["-t", "4242", "-n", "--", "curl", "-K", "-"]);
    assert!(
        String::from_utf8_lossy(stdin.as_deref().unwrap()).contains("/api/auth/token"),
        "die Probe gehoert per stdin in curl"
    );
    // Und das Urteil kommt vom Wirts-curl, nicht vom Gast.
    assert_eq!(v.label(), "failed", "{v:?}");
}

/// B112, Nachtrag: Der enge Deckel gehoert an das, was ein GAST liefert —
/// nicht an rustic, dessen Liste ueber das ganze Repo am Server weit ueber
/// 1 MiB hat (0.2.0 endete dort mit jedem Lauf bei Exit 2).
#[test]
fn b112_deckel_je_aufruf_gast_eng_rustic_weit() {
    let cfg = parse(include_str!("answers/signoff.toml")).unwrap();
    let s = cfg.service("ghostfolio").unwrap();
    let fake = Fake::new()
        .on("machinectl", "Leader", out(0, "4242\n", ""))
        .on("nsenter", "", out(0, "401", ""));
    factory_login::check(&fake, s);
    assert_eq!(fake.limits(), vec![Limits::HOST, Limits::GUEST]);

    let fake = Fake::new().on(
        "rustic",
        "",
        out(0, include_str!("answers/rustic-fin-01.json"), ""),
    );
    let _ = backup::control_repo(&fake, &cfg);
    let _ = backup::check(&fake, &cfg, s, 0);
    assert_eq!(fake.limits(), vec![Limits::RUSTIC, Limits::RUSTIC]);
    const { assert!(Limits::RUSTIC.deckel >= 64 << 20) };
    const { assert!(Limits::GUEST.deckel <= 1 << 20) };
}
