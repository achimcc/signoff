//! Run a program inside an nspawn guest: `systemd-run --machine=` with the
//! three switches that are not optional here (`--wait`: otherwise the
//! output is empty; `--pipe`: otherwise there is no output at all;
//! `--collect`: otherwise a red transient unit stays behind) and an
//! ABSOLUTE program path (`--machine=` does not search PATH).

use crate::curlrc::CurlRc;
use crate::runner::{Limits, Output, Runner};

pub const SYSTEMD_RUN: &str = "systemd-run";
pub const CURL: &str = "/run/current-system/sw/bin/curl";
pub const MACHINECTL: &str = "machinectl";
pub const NSENTER: &str = "nsenter";
/// Das curl des WIRTS, ueber dessen PATH — wie `public-path`. `nsenter -n`
/// wechselt nur den Netz-Namensraum, der Pfad wird also im Dateisystem des
/// Wirts aufgeloest, nie in dem des Gastes.
pub const HOST_CURL: &str = "curl";
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
    let out = r.run_with(
        SYSTEMD_RUN,
        &args(guest, program, argv),
        stdin,
        Limits::GUEST,
    )?;
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

/// Die Leader-PID eines Gastes, wie machined sie kennt.
pub fn leader(r: &dyn Runner, guest: &str) -> Result<u32, String> {
    let out = r.run(
        MACHINECTL,
        &[
            "show".into(),
            guest.into(),
            "--property=Leader".into(),
            "--value".into(),
        ],
        None,
    )?;
    match out.stdout.trim().parse::<u32>() {
        // 0 und 1 waeren der Wirt selbst — dort misst diese Probe nie.
        Ok(pid) if out.code == Some(0) && pid > 1 => Ok(pid),
        _ => Err(format!(
            "machinectl names no leader for {guest} (exit {:?}): {}",
            out.code,
            out.stderr.trim().lines().next().unwrap_or("")
        )),
    }
}

/// curl des WIRTS im Netz-Namensraum des Gastes (Audit 3, B113).
///
/// `curl` oben fuehrt das curl aus dem Profil des GASTES aus — ein
/// uebernommener Gast bestimmt damit, was die Probe sieht (ein curl, das
/// immer `401` sagt, macht jedes Werkskonto „abgewiesen“). Hier laeuft das
/// Programm des Wirts; der Gast stellt nur das Netz, und das ist derselbe
/// Standpunkt wie vorher: dieselben Adressen, dieselbe Firewall. Der Weg
/// ist der von groundtruth (`nsenter -t <leader> -n`). Die Probe geht wie
/// immer per stdin, nie in argv.
///
/// `nsenter -n` braucht CAP_SYS_ADMIN (setns) und CAP_SYS_PTRACE (die
/// Namensraum-Datei des Leaders). Fehlt eins, antwortet nsenter selbst mit
/// Exit 1 — das wird hier als „nicht messbar“ benannt, nicht als curl-Fehler.
pub fn host_curl_in_netns(r: &dyn Runner, guest: &str, rc: &CurlRc) -> Result<Output, String> {
    let pid = leader(r, guest)?.to_string();
    // Das Programm ist des Wirts, die ANTWORT kommt vom Dienst im Gast —
    // deshalb der enge Deckel.
    let out = r.run_with(
        NSENTER,
        &[
            "-t".into(),
            pid,
            "-n".into(),
            "--".into(),
            HOST_CURL.into(),
            "-K".into(),
            "-".into(),
        ],
        Some(&rc.render()),
        Limits::GUEST,
    )?;
    if let Some(zeile) = out.stderr.lines().find(|z| z.starts_with("nsenter:")) {
        return Err(format!(
            "cannot enter the network namespace of {guest}: {zeile}"
        ));
    }
    Ok(out)
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
    fn host_curl_betritt_nur_das_netz_des_leaders() {
        let fake = Fake::new()
            .on(
                "machinectl",
                "fin-01 --property=Leader",
                Output {
                    code: Some(0),
                    stdout: "4242\n".into(),
                    stderr: String::new(),
                },
            )
            .on(
                "nsenter",
                "",
                Output {
                    code: Some(0),
                    stdout: "401".into(),
                    stderr: String::new(),
                },
            );
        let rc = CurlRc::new("http://10.0.190.10:3333/").code_only();
        let out = host_curl_in_netns(&fake, "fin-01", &rc).unwrap();
        assert_eq!(out.stdout, "401");
        let (prog, argv, stdin) = &fake.calls()[1];
        assert_eq!(prog, "nsenter");
        assert_eq!(argv, &["-t", "4242", "-n", "--", "curl", "-K", "-"]);
        assert!(
            String::from_utf8(stdin.clone().unwrap())
                .unwrap()
                .contains("http://10.0.190.10:3333/")
        );
    }

    #[test]
    fn ohne_leader_oder_ohne_setns_ist_es_nicht_messbar() {
        let aus = |code, stdout: &str, stderr: &str| Output {
            code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        };
        let rc = CurlRc::new("http://x/").code_only();
        for (code, stdout) in [
            (0, ""),
            (0, "0\n"),
            (0, "1\n"),
            (1, "4242\n"),
            (0, "4242 x"),
        ] {
            let fake = Fake::new().on(
                "machinectl",
                "",
                aus(code, stdout, "Could not get path to machine"),
            );
            let e = host_curl_in_netns(&fake, "fin-01", &rc).unwrap_err();
            assert!(
                e.starts_with("machinectl names no leader for fin-01"),
                "{e}"
            );
            assert_eq!(fake.calls().len(), 1, "ohne Leader kein nsenter");
        }
        let fake = Fake::new().on("machinectl", "", aus(0, "4242\n", "")).on(
            "nsenter",
            "",
            aus(
                1,
                "",
                "nsenter: reassociate to namespace 'ns/net' failed: Operation not permitted\n",
            ),
        );
        assert_eq!(
            host_curl_in_netns(&fake, "fin-01", &rc).unwrap_err(),
            "cannot enter the network namespace of fin-01: nsenter: reassociate to namespace 'ns/net' failed: Operation not permitted"
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
