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

pub trait Runner {
    /// Runs `program` with `args`, writes `stdin` (if any) and closes it.
    /// `Err` only when the program cannot be started at all.
    fn run(&self, program: &str, args: &[String], stdin: Option<&[u8]>) -> Result<Output, String>;
}

/// Fuehrt Befehle wirklich aus — mit Frist und Lesedeckel (Audit 3, B112).
///
/// Bis v0.1.1 lief jeder Befehl ueber `wait_with_output`: ohne Zeitgrenze
/// und mit allem, was er schrieb, im Speicher. `max-time 15` stand nur in der
/// curl-Konfiguration, und die kann ein Gast-curl ignorieren; `systemd-run
/// --wait` selbst wartet ewig. Ein Gast hielt so den taeglichen Lauf bis zur
/// `TimeoutStartSec` der Unit fest oder schob beliebig viel stdout in den
/// Speicher. Beides endet jetzt HIER, fuer jeden Befehl, als `Err` — und
/// jeder Pruefer macht aus einem `Err` `cannot measure`.
pub struct System {
    /// Laenger darf ein einzelner Befehl nicht laufen; danach wird er beendet.
    pub frist: Duration,
    /// Mehr Bytes je Strom (stdout, stderr) werden nicht gelesen; wer mehr
    /// schreibt, wird beendet, die Ausgabe verworfen.
    pub deckel: usize,
}

impl System {
    /// Zwei Minuten: curl hat 15 s, dig Sekunden; das Langsamste ist rustic,
    /// das den Index des ganzen Repos liest. Die Frist ist das Netz darunter,
    /// nicht die Messung.
    pub const FRIST: Duration = Duration::from_secs(120);
    /// 1 MiB: die groesste echte Antwort (Authentiks Providerliste, rustics
    /// Snapshots eines Gastes) liegt weit darunter.
    pub const DECKEL: usize = 1 << 20;
}

impl Default for System {
    fn default() -> System {
        System {
            frist: System::FRIST,
            deckel: System::DECKEL,
        }
    }
}

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
    fn run(&self, program: &str, args: &[String], stdin: Option<&[u8]>) -> Result<Output, String> {
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
        let ende = Instant::now() + self.frist;
        // Beide Stroeme in eigenen Faeden: ein voller stderr darf stdout nicht
        // blockieren. Die Faeden werden nie `join`t, sondern ueber einen Kanal
        // mit Frist abgefragt — ein Enkel (der Prozess im Gast hinter
        // `systemd-run --pipe`) kann die Leitung offen halten, nachdem das
        // Kind selbst schon beendet ist.
        let aus = lies_gedeckelt(
            child.stdout.take().ok_or("stdout pipe missing")?,
            self.deckel,
        );
        let err = lies_gedeckelt(
            child.stderr.take().ok_or("stderr pipe missing")?,
            self.deckel,
        );
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
                self.frist.as_secs()
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
            if gelesen.iter().flatten().any(|v| v.len() > self.deckel) {
                return beenden(
                    &mut child,
                    format!(
                        "{program}: more than {} bytes of output — killed, output discarded",
                        self.deckel
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
            if v.len() > self.deckel {
                return Err(format!(
                    "{program}: more than {} bytes of output — output discarded",
                    self.deckel
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
}

impl Runner for Fake {
    fn run(&self, program: &str, args: &[String], stdin: Option<&[u8]>) -> Result<Output, String> {
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
        let out = System::default()
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
        let out = System::default()
            .run("cat", &[], Some(b"via stdin"))
            .unwrap();
        assert_eq!(out.stdout, "via stdin");
    }

    #[test]
    fn system_runner_reports_a_missing_program_as_err() {
        assert!(
            System::default()
                .run("/nonexistent/program", &[], None)
                .is_err()
        );
    }

    fn eng(frist_ms: u64, deckel: usize) -> System {
        System {
            frist: Duration::from_millis(frist_ms),
            deckel,
        }
    }

    #[test]
    fn system_runner_beendet_einen_befehl_nach_der_frist() {
        let start = Instant::now();
        let e = eng(300, 1024)
            .run("sh", &["-c".into(), "sleep 10".into()], None)
            .unwrap_err();
        assert!(e.contains("still running after"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn system_runner_wartet_nicht_auf_einen_enkel_der_die_leitung_haelt() {
        // Das Kind endet sofort, der Enkel haelt stdout offen — wie der
        // Prozess im Gast hinter `systemd-run --pipe`.
        let start = Instant::now();
        let e = eng(300, 1024)
            .run("sh", &["-c".into(), "sleep 10 & echo weg".into()], None)
            .unwrap_err();
        assert!(e.contains("still running after"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn system_runner_verwirft_mehr_als_den_deckel() {
        let start = Instant::now();
        let e = eng(10_000, 1024)
            .run("sh", &["-c".into(), "yes".into()], None)
            .unwrap_err();
        assert!(e.contains("more than 1024 bytes"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5));
        // Auf stderr ebenso.
        let e = eng(10_000, 1024)
            .run(
                "sh",
                &["-c".into(), "head -c 5000 /dev/zero >&2".into()],
                None,
            )
            .unwrap_err();
        assert!(e.contains("more than 1024 bytes"), "{e}");
        // Genau am Deckel ist es noch eine Antwort.
        let out = eng(10_000, 1024)
            .run("sh", &["-c".into(), "head -c 1024 /dev/zero".into()], None)
            .unwrap();
        assert_eq!(out.stdout.len(), 1024);
    }

    #[test]
    fn system_runner_haengt_nicht_an_einem_befehl_der_stdin_nicht_liest() {
        let viel = vec![b'x'; 4 << 20];
        let out = eng(5_000, 1024)
            .run("sh", &["-c".into(), "exit 4".into()], Some(&viel))
            .unwrap();
        assert_eq!(out.code, Some(4));
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
