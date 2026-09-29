//! Every external command goes through here. `System` runs it; `Fake`
//! replays recorded answers so the verdict logic is testable without a host.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// `None` when the process was killed by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Frist und Lesedeckel EINES Aufrufs (Audit 3, B112) — je Aufruf gesetzt,
/// nicht global: Was ein Gast liefert, bekommt den engen Deckel; was ein
/// Werkzeug des Wirts ueber eigene Daten sagt, einen weiten. Der erste
/// Wurf (0.2.0) hatte 1 MiB fuer alles, und die Positivkontrolle
/// `rustic snapshots --json` ueber das ganze Repo (rund 2000 Snapshots)
/// liefert weit mehr — jeder Lauf am Server endete mit Exit 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Laenger darf der Aufruf nicht laufen; danach wird er beendet.
    pub frist: Duration,
    /// Mehr Bytes je Strom (stdout, stderr) werden nicht gelesen; wer mehr
    /// schreibt, wird beendet, die Ausgabe verworfen.
    pub deckel: usize,
}

impl Limits {
    /// Programme IM Gast (`systemd-run --machine`) und alles, was im Netz
    /// eines Gastes dessen Antwort holt (`nsenter -n … curl`, vantage). Die
    /// groesste echte Antwort ist Authentiks Providerliste, wenige KiB.
    pub const GUEST: Limits = Limits {
        frist: Duration::from_secs(120),
        deckel: 1 << 20,
    };
    /// Werkzeuge des Wirts ueber Daten, die kein Gast schreibt (dig, das
    /// curl von public-path, machinectl). Der Deckel ist nur noch das Netz
    /// gegen einen Fehler, nicht gegen einen Gegner.
    pub const HOST: Limits = Limits {
        frist: Duration::from_secs(120),
        deckel: 64 << 20,
    };
    /// rustic liest fuer JEDE Liste alle Snapshot-Dateien des Repos (auch
    /// mit `--filter-label` — gefiltert wird danach) und entschluesselt sie.
    /// Bei rund 2000 Snapshots ist das NICHT gemessen; die Frist ist deshalb
    /// grosszuegig, ein zu knapper Wert haette jeden Lauf zu „nicht messbar“
    /// gemacht, und die Unit hat darueber noch ihre `TimeoutStartSec`.
    pub const RUSTIC: Limits = Limits {
        frist: Duration::from_secs(600),
        deckel: 64 << 20,
    };
}

pub trait Runner {
    /// Runs `program` with `args`, writes `stdin` (if any) and closes it,
    /// within `limits`. `Err` when the program cannot be started at all, or
    /// ran longer or wrote more than `limits` allow.
    fn run_with(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&[u8]>,
        limits: Limits,
    ) -> Result<Output, String>;

    /// Ein Aufruf eines Wirtswerkzeugs: `Limits::HOST`.
    fn run(&self, program: &str, args: &[String], stdin: Option<&[u8]>) -> Result<Output, String> {
        self.run_with(program, args, stdin, Limits::HOST)
    }
}

/// Fuehrt Befehle wirklich aus — mit Frist und Lesedeckel je Aufruf
/// (Audit 3, B112, s. `Limits`).
///
/// Bis v0.1.1 lief jeder Befehl ueber `wait_with_output`: ohne Zeitgrenze
/// und mit allem, was er schrieb, im Speicher. `max-time 15` stand nur in der
/// curl-Konfiguration, und die kann ein Gast-curl ignorieren; `systemd-run
/// --wait` selbst wartet ewig. Ein Gast hielt so den taeglichen Lauf bis zur
/// `TimeoutStartSec` der Unit fest oder schob beliebig viel stdout in den
/// Speicher. Beides endet jetzt HIER als `Err` — und jeder Pruefer macht aus
/// einem `Err` `cannot measure`.
pub struct System;

/// Liest hoechstens `deckel + 1` Bytes aus `quelle` — das eine Byte mehr
/// zeigt, dass der Deckel ueberschritten ist.
fn lies_gedeckelt(quelle: impl Read + Send + 'static, deckel: usize) -> Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = quelle.take(deckel as u64 + 1).read_to_end(&mut v);
        let _ = tx.send(v);
    });
    rx
}

impl Runner for System {
    fn run_with(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&[u8]>,
        limits: Limits,
    ) -> Result<Output, String> {
        let Limits { frist, deckel } = limits;
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("{program}: {e}"))?;
        let ende = Instant::now() + frist;
        // Beide Stroeme in eigenen Faeden: ein voller stderr darf stdout nicht
        // blockieren. Die Faeden werden nie `join`t, sondern ueber einen Kanal
        // mit Frist abgefragt — ein Enkel (der Prozess im Gast hinter
        // `systemd-run --pipe`) kann die Leitung offen halten, nachdem das
        // Kind selbst schon beendet ist.
        let aus = lies_gedeckelt(child.stdout.take().ok_or("stdout pipe missing")?, deckel);
        let err = lies_gedeckelt(child.stderr.take().ok_or("stderr pipe missing")?, deckel);
        // stdin ebenfalls im eigenen Faden: ein Befehl, der nicht liest, liesse
        // `write_all` sonst an der vollen Leitung haengen — vor jeder Frist.
        if let Some(bytes) = stdin {
            let mut pipe = child.stdin.take().ok_or("stdin pipe missing")?;
            let bytes = bytes.to_vec();
            std::thread::spawn(move || {
                let _ = pipe.write_all(&bytes);
            });
        }
        let beenden = |child: &mut std::process::Child, warum: String| {
            let _ = child.kill();
            let _ = child.wait();
            Err(warum)
        };
        let abgelaufen = || {
            format!(
                "{program}: still running after {} s — killed (signoff's own limit)",
                frist.as_secs()
            )
        };
        let mut gelesen: [Option<Vec<u8>>; 2] = [None, None];
        let status = loop {
            for (slot, rx) in gelesen.iter_mut().zip([&aus, &err]) {
                if slot.is_none()
                    && let Ok(v) = rx.try_recv()
                {
                    *slot = Some(v);
                }
            }
            // Der Deckel wirkt, sobald ein Strom ihn reisst — nicht erst nach
            // dem Ende des Kindes, das an der vollen Leitung sonst bis zur
            // Frist wartete.
            if gelesen.iter().flatten().any(|v| v.len() > deckel) {
                return beenden(
                    &mut child,
                    format!(
                        "{program}: more than {} bytes of output — killed, output discarded",
                        deckel
                    ),
                );
            }
            match child.try_wait().map_err(|e| format!("{program}: {e}"))? {
                Some(s) => break s,
                None if Instant::now() >= ende => return beenden(&mut child, abgelaufen()),
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        // Das Kind ist beendet; was die Faeden noch haben, kommt bis zur Frist.
        let mut stroeme = Vec::with_capacity(2);
        for (slot, rx) in gelesen.into_iter().zip([aus, err]) {
            let v = match slot {
                Some(v) => v,
                None => rx
                    .recv_timeout(ende.saturating_duration_since(Instant::now()))
                    .map_err(|_| abgelaufen())?,
            };
            if v.len() > deckel {
                return Err(format!(
                    "{program}: more than {} bytes of output — output discarded",
                    deckel
                ));
            }
            stroeme.push(String::from_utf8_lossy(&v).into_owned());
        }
        let stderr = stroeme.pop().unwrap_or_default();
        let stdout = stroeme.pop().unwrap_or_default();
        Ok(Output {
            code: status.code(),
            stdout,
            stderr,
        })
    }
}

struct Rule {
    program: String,
    args_contain: String,
    output: Output,
}

/// One recorded invocation: program, arguments, stdin (if any).
type Call = (String, Vec<String>, Option<Vec<u8>>);

#[derive(Default)]
pub struct Fake {
    rules: Vec<Rule>,
    calls: RefCell<Vec<Call>>,
    limits: RefCell<Vec<Limits>>,
}

impl Fake {
    pub fn new() -> Fake {
        Fake::default()
    }
    /// Answer `output` when `program` matches and the space-joined arguments
    /// plus the stdin text contain `args_contain` (a URL that only travels in
    /// a curl config via stdin is matchable, too). The first matching rule wins.
    pub fn on(mut self, program: &str, args_contain: &str, output: Output) -> Fake {
        self.rules.push(Rule {
            program: program.into(),
            args_contain: args_contain.into(),
            output,
        });
        self
    }
    pub fn calls(&self) -> Vec<Call> {
        self.calls.borrow().clone()
    }
    /// Die `Limits` jedes Aufrufs, in derselben Reihenfolge wie `calls`.
    pub fn limits(&self) -> Vec<Limits> {
        self.limits.borrow().clone()
    }
}

impl Runner for Fake {
    fn run_with(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&[u8]>,
        limits: Limits,
    ) -> Result<Output, String> {
        self.limits.borrow_mut().push(limits);
        self.calls
            .borrow_mut()
            .push((program.into(), args.to_vec(), stdin.map(|b| b.to_vec())));
        let joined = args.join(" ");
        let stdin_text = stdin
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let haystack = format!("{joined}\n{stdin_text}");
        self.rules
            .iter()
            .find(|r| r.program == program && haystack.contains(&r.args_contain))
            .map(|r| r.output.clone())
            .ok_or_else(|| format!("fake runner: no rule for {program} {joined}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_runner_captures_code_stdout_and_stderr() {
        let out = System
            .run(
                "sh",
                &["-c".into(), "echo out; echo err >&2; exit 3".into()],
                None,
            )
            .unwrap();
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stdout, "out\n");
        assert_eq!(out.stderr, "err\n");
    }

    #[test]
    fn system_runner_feeds_stdin() {
        let out = System.run("cat", &[], Some(b"via stdin")).unwrap();
        assert_eq!(out.stdout, "via stdin");
    }

    #[test]
    fn system_runner_reports_a_missing_program_as_err() {
        assert!(System.run("/nonexistent/program", &[], None).is_err());
    }

    /// Ein System-Aufruf mit eigenen Grenzen.
    fn mit(
        frist_ms: u64,
        deckel: usize,
        program: &str,
        skript: &str,
        stdin: Option<&[u8]>,
    ) -> Result<Output, String> {
        System.run_with(
            program,
            &["-c".into(), skript.into()],
            stdin,
            Limits {
                frist: Duration::from_millis(frist_ms),
                deckel,
            },
        )
    }

    #[test]
    fn system_runner_beendet_einen_befehl_nach_der_frist() {
        let start = Instant::now();
        let e = mit(300, 1024, "sh", "sleep 10", None).unwrap_err();
        assert!(e.contains("still running after"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn system_runner_wartet_nicht_auf_einen_enkel_der_die_leitung_haelt() {
        // Das Kind endet sofort, der Enkel haelt stdout offen — wie der
        // Prozess im Gast hinter `systemd-run --pipe`.
        let start = Instant::now();
        let e = mit(300, 1024, "sh", "sleep 10 & echo weg", None).unwrap_err();
        assert!(e.contains("still running after"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn system_runner_verwirft_mehr_als_den_deckel() {
        let start = Instant::now();
        let e = mit(10_000, 1024, "sh", "yes", None).unwrap_err();
        assert!(e.contains("more than 1024 bytes"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5));
        // Auf stderr ebenso.
        let e = mit(10_000, 1024, "sh", "head -c 5000 /dev/zero >&2", None).unwrap_err();
        assert!(e.contains("more than 1024 bytes"), "{e}");
        // Genau am Deckel ist es noch eine Antwort.
        let out = mit(10_000, 1024, "sh", "head -c 1024 /dev/zero", None).unwrap();
        assert_eq!(out.stdout.len(), 1024);
    }

    #[test]
    fn system_runner_haengt_nicht_an_einem_befehl_der_stdin_nicht_liest() {
        let viel = vec![b'x'; 4 << 20];
        let out = mit(5_000, 1024, "sh", "exit 4", Some(&viel)).unwrap();
        assert_eq!(out.code, Some(4));
    }

    #[test]
    fn der_deckel_haengt_am_aufruf_nicht_am_runner() {
        // 2 MiB: fuer ein Wirtswerkzeug (rustics Snapshotliste) eine
        // Antwort, fuer einen Gast zu viel. Mit einem Pauschaldeckel von
        // 1 MiB (0.2.0) war der erste Fall rot — und am Server jeder Lauf.
        let zwei_mib = "head -c 2097152 /dev/zero".to_string();
        let wirt = System
            .run("sh", &["-c".into(), zwei_mib.clone()], None)
            .unwrap();
        assert_eq!(wirt.stdout.len(), 2 << 20);
        let rustic = System
            .run_with("sh", &["-c".into(), zwei_mib.clone()], None, Limits::RUSTIC)
            .unwrap();
        assert_eq!(rustic.stdout.len(), 2 << 20);
        let gast = System
            .run_with("sh", &["-c".into(), zwei_mib], None, Limits::GUEST)
            .unwrap_err();
        assert!(gast.contains("more than 1048576 bytes"), "{gast}");
    }

    #[test]
    fn fake_matches_program_and_argument_substring_first_rule_wins() {
        let fake = Fake::new()
            .on(
                "dig",
                "AAAA",
                Output {
                    code: Some(0),
                    stdout: "2a01::1\n".into(),
                    stderr: String::new(),
                },
            )
            .on(
                "dig",
                "",
                Output {
                    code: Some(0),
                    stdout: "77.42.71.141\n".into(),
                    stderr: String::new(),
                },
            );
        let a = fake
            .run("dig", &["+short".into(), "A".into(), "x".into()], None)
            .unwrap();
        assert_eq!(a.stdout, "77.42.71.141\n");
        let aaaa = fake
            .run("dig", &["+short".into(), "AAAA".into(), "x".into()], None)
            .unwrap();
        assert_eq!(aaaa.stdout, "2a01::1\n");
        assert!(fake.run("curl", &[], None).is_err());
        let via_stdin = Fake::new().on(
            "curl",
            "url = \"http://x/\"",
            Output {
                code: Some(0),
                stdout: "ok".into(),
                stderr: String::new(),
            },
        );
        assert_eq!(
            via_stdin
                .run(
                    "curl",
                    &["-K".into(), "-".into()],
                    Some(b"url = \"http://x/\"\n")
                )
                .unwrap()
                .stdout,
            "ok"
        );
        assert_eq!(fake.calls().len(), 3);
        assert_eq!(fake.calls()[0].0, "dig");
    }
}
