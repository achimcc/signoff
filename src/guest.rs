//! Run a program inside an nspawn guest: `systemd-run --machine=` with the
//! three switches that are not optional here (`--wait`: otherwise the
//! output is empty; `--pipe`: otherwise there is no output at all;
//! `--collect`: otherwise a red transient unit stays behind) and an
//! ABSOLUTE program path (`--machine=` does not search PATH).

use crate::curlrc::CurlRc;
use crate::runner::{Output, Runner};

pub const SYSTEMD_RUN: &str = "systemd-run";
pub const CURL: &str = "/run/current-system/sw/bin/curl";
pub const KURZTOKEN: &str = "/run/current-system/sw/bin/authentik-kurztoken";

pub fn args(guest: &str, program: &str, args: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = vec![
        format!("--machine={guest}"),
        "--wait".into(),
        "--pipe".into(),
        "--quiet".into(),
        "--collect".into(),
        "--".into(),
        program.into(),
    ];
    v.extend(args.iter().map(|a| a.to_string()));
    v
}

pub fn run(
    r: &dyn Runner,
    guest: &str,
    program: &str,
    argv: &[&str],
    stdin: Option<&[u8]>,
) -> Result<Output, String> {
    let out = r.run(SYSTEMD_RUN, &args(guest, program, argv), stdin)?;
    if out.code == Some(203) {
        return Err(format!(
            "{program} is not in the profile of {guest} (203/EXEC)"
        ));
    }
    Ok(out)
}

pub fn curl(r: &dyn Runner, guest: &str, rc: &CurlRc) -> Result<Output, String> {
    run(r, guest, CURL, &["-K", "-"], Some(&rc.render()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{Fake, Output};

    #[test]
    fn systemd_run_gets_all_five_switches_and_an_absolute_program() {
        let a = args("auth-01", KURZTOKEN, &["signoff"]);
        assert_eq!(
            a,
            vec![
                "--machine=auth-01",
                "--wait",
                "--pipe",
                "--quiet",
                "--collect",
                "--",
                KURZTOKEN,
                "signoff"
            ]
        );
    }

    #[test]
    fn curl_goes_through_stdin_not_argv() {
        let fake = Fake::new().on(
            "systemd-run",
            "curl -K -",
            Output {
                code: Some(0),
                stdout: "200".into(),
                stderr: String::new(),
            },
        );
        let rc = CurlRc::new("http://x/")
            .header("Authorization", "Bearer SECRET")
            .code_only();
        let out = curl(&fake, "auth-01", &rc).unwrap();
        assert_eq!(out.stdout, "200");
        let (_, argv, stdin) = &fake.calls()[0];
        assert!(!argv.join(" ").contains("SECRET"));
        assert!(
            String::from_utf8(stdin.clone().unwrap())
                .unwrap()
                .contains("Bearer SECRET")
        );
    }

    #[test]
    fn exec_failure_names_the_guest() {
        let fake = Fake::new().on(
            "systemd-run",
            "",
            Output {
                code: Some(203),
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        let e = run(&fake, "koch-01", CURL, &["-V"], None).unwrap_err();
        assert_eq!(
            e,
            "/run/current-system/sw/bin/curl is not in the profile of koch-01 (203/EXEC)"
        );
    }

    #[test]
    fn other_exit_codes_are_returned_not_errors() {
        let fake = Fake::new().on(
            "systemd-run",
            "",
            Output {
                code: Some(22),
                stdout: String::new(),
                stderr: "curl: (22)".into(),
            },
        );
        assert_eq!(run(&fake, "g", CURL, &[], None).unwrap().code, Some(22));
    }
}
