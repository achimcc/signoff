//! Every external command goes through here. `System` runs it; `Fake`
//! replays recorded answers so the verdict logic is testable without a host.

use std::cell::RefCell;
use std::io::Write;
use std::process::{Command, Stdio};

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

pub struct System;

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
        if let Some(bytes) = stdin {
            let mut pipe = child.stdin.take().ok_or("stdin pipe missing")?;
            pipe.write_all(bytes)
                .map_err(|e| format!("{program}: writing stdin: {e}"))?;
            drop(pipe);
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("{program}: {e}"))?;
        Ok(Output {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
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
