//! The five verdicts, one line per measurement, and the three exit codes.
//!
//! `n/a` and `undeclared` never change the exit code: the first says the
//! question does not apply to this service, the second says nobody has
//! declared a probe yet — visible, but not a finding.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok(String),
    Failed(String),
    CannotMeasure(String),
    NotApplicable(String),
    Undeclared(String),
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Ok(_) => "ok",
            Verdict::Failed(_) => "failed",
            Verdict::CannotMeasure(_) => "cannot measure",
            Verdict::NotApplicable(_) => "n/a",
            Verdict::Undeclared(_) => "undeclared",
        }
    }
    pub fn detail(&self) -> &str {
        match self {
            Verdict::Ok(d)
            | Verdict::Failed(d)
            | Verdict::CannotMeasure(d)
            | Verdict::NotApplicable(d)
            | Verdict::Undeclared(d) => d,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub service: String,
    pub check: &'static str,
    pub verdict: Verdict,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Summary {
    pub ok: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub undeclared: usize,
    pub cannot_measure: usize,
}

impl Summary {
    pub fn of(findings: &[Finding]) -> Summary {
        let mut s = Summary::default();
        for f in findings {
            match f.verdict {
                Verdict::Ok(_) => s.ok += 1,
                Verdict::Failed(_) => s.failed += 1,
                Verdict::CannotMeasure(_) => s.cannot_measure += 1,
                Verdict::NotApplicable(_) => s.not_applicable += 1,
                Verdict::Undeclared(_) => s.undeclared += 1,
            }
        }
        s
    }

    /// 2: at least one measurement could not be taken — the run says
    /// nothing complete. 1: a finding. 0: everything measured, everything ok.
    pub fn exit_code(&self) -> i32 {
        if self.cannot_measure > 0 {
            2
        } else if self.failed > 0 {
            1
        } else {
            0
        }
    }

    pub fn line(&self) -> String {
        format!(
            "{} ok, {} failed, {} n/a, {} undeclared, {} cannot measure",
            self.ok, self.failed, self.not_applicable, self.undeclared, self.cannot_measure
        )
    }
}

/// Hoechstens so viele Zeichen je Detail — eine Berichtszeile, kein Dump.
pub const DETAIL_MAX: usize = 300;

/// Macht einen Text fuer Terminal, Journal und Alarmmail ungefaehrlich
/// (Audit 3, B112). Ein Detail traegt oft, was ein Gast geliefert hat
/// (die erste stderr-Zeile seines curl, Namen aus Authentik): Ein roher
/// `ESC ] 52` schreibt in vielen Terminals die Zwischenablage, `ESC [ 2 J`
/// loescht den Schirm, ein Zeilenumbruch erfindet eine zweite Berichtszeile,
/// und eine Bidi-Steuerung (U+202E) dreht die Leserichtung um. Jedes davon
/// wird SICHTBAR geschrieben (`\x1b`, `\u{202e}`), nichts faellt still weg —
/// wer den Bericht liest, soll sehen, dass da etwas war. Nur der Tabulator
/// bleibt. Laenger als `DETAIL_MAX` Zeichen wird abgeschnitten, mit `…`.
pub fn sanitize(text: &str) -> String {
    let mut aus = String::with_capacity(text.len().min(DETAIL_MAX * 2));
    for (n, c) in text.chars().enumerate() {
        if n == DETAIL_MAX {
            aus.push('…');
            break;
        }
        let bidi = matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        if (c.is_control() && c != '\t') || bidi {
            if (c as u32) < 0x80 {
                aus.push_str(&format!("\\x{:02x}", c as u32));
            } else {
                aus.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
        } else {
            aus.push(c);
        }
    }
    aus
}

/// Die eine Stelle, durch die jedes Urteil in den Bericht geht — deshalb
/// wird HIER gesaeubert und nicht bei jedem der Pruefer (Audit 3, B112).
pub fn format_line(f: &Finding) -> String {
    format!(
        "{:<15} {:<15} {:<16} {}",
        sanitize(&f.service),
        f.check,
        f.verdict.label(),
        sanitize(f.verdict.detail())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(check: &'static str, v: Verdict) -> Finding {
        Finding {
            service: "ghostfolio".into(),
            check,
            verdict: v,
        }
    }

    #[test]
    fn sanitize_macht_steuerzeichen_sichtbar_und_kuerzt() {
        assert_eq!(
            sanitize("a\x1b[2Jb\x07\nc\td\u{202e}e"),
            "a\\x1b[2Jb\\x07\\x0ac\td\\u{202e}e"
        );
        // C1-Steuerzeichen (U+009B ist ein einzelnes CSI) ebenso.
        assert_eq!(sanitize("\u{9b}2J"), "\\u{9b}2J");
        assert_eq!(sanitize("ok HTTP 401"), "ok HTTP 401");
        let lang = sanitize(&"x".repeat(DETAIL_MAX + 50));
        assert_eq!(lang.chars().count(), DETAIL_MAX + 1);
        assert!(lang.ends_with('…'));
    }

    #[test]
    fn labels_are_the_five_from_the_spec() {
        assert_eq!(Verdict::Ok("x".into()).label(), "ok");
        assert_eq!(Verdict::Failed("x".into()).label(), "failed");
        assert_eq!(Verdict::CannotMeasure("x".into()).label(), "cannot measure");
        assert_eq!(Verdict::NotApplicable("no backend".into()).label(), "n/a");
        assert_eq!(Verdict::Undeclared("x".into()).label(), "undeclared");
    }

    #[test]
    fn exit_code_two_beats_one_beats_zero() {
        let all_ok = Summary::of(&[f("dns-a", Verdict::Ok("77.42.71.141".into()))]);
        assert_eq!(all_ok.exit_code(), 0);
        let one_failed = Summary::of(&[
            f("dns-a", Verdict::Ok("x".into())),
            f("backend", Verdict::Failed("dropped at zone edge".into())),
        ]);
        assert_eq!(one_failed.exit_code(), 1);
        let cannot = Summary::of(&[
            f("backend", Verdict::Failed("x".into())),
            f("backup", Verdict::CannotMeasure("rustic exit 1".into())),
        ]);
        assert_eq!(cannot.exit_code(), 2);
    }

    #[test]
    fn na_and_undeclared_do_not_change_the_exit_code() {
        let s = Summary::of(&[
            f("outpost", Verdict::NotApplicable("no forward_auth".into())),
            f(
                "factory-login",
                Verdict::Undeclared("no probe declared".into()),
            ),
        ]);
        assert_eq!(s.exit_code(), 0);
        assert_eq!(s.not_applicable, 1);
        assert_eq!(s.undeclared, 1);
    }

    #[test]
    fn line_has_service_check_label_detail_in_columns() {
        let l = format_line(&f(
            "public-path",
            Verdict::Ok("HTTP 302 via 77.42.71.141".into()),
        ));
        assert_eq!(
            l,
            "ghostfolio      public-path     ok               HTTP 302 via 77.42.71.141"
        );
        let l = format_line(&f(
            "outpost",
            Verdict::NotApplicable("no forward_auth".into()),
        ));
        assert_eq!(
            l,
            "ghostfolio      outpost         n/a              no forward_auth"
        );
    }

    #[test]
    fn summary_line_counts_every_kind() {
        let s = Summary::of(&[
            f("dns-a", Verdict::Ok("x".into())),
            f("dns-aaaa", Verdict::Ok("x".into())),
            f("backend", Verdict::Failed("x".into())),
            f("outpost", Verdict::NotApplicable("x".into())),
            f("factory-login", Verdict::Undeclared("x".into())),
        ]);
        assert_eq!(
            s.line(),
            "2 ok, 1 failed, 1 n/a, 1 undeclared, 0 cannot measure"
        );
    }
}
