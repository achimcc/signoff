//! Command line → `Cmd`, with lexopt. Small grammar, every branch a test.

use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    Check { services: Vec<String>, all: bool },
    Plan { services: Vec<String>, all: bool },
    Rules,
    Help,
    Version,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub config: PathBuf,
    pub cmd: Cmd,
}

pub const USAGE: &str = "\
usage: signoff [--config /etc/signoff.toml] check (<service>… | --all)
       signoff [--config …] plan  (<service>… | --all)
       signoff rules
       signoff --help | --version

Runs on the host as root. Exit 0: everything measured, everything ok.
Exit 1: at least one `failed`. Exit 2: a control or a measurement could not
be taken — the run says nothing complete.";

pub fn parse(argv: &[String]) -> Result<Args, String> {
    use lexopt::prelude::*;
    // `from_iter` expects argv[0] to be the binary name and discards it; our
    // `argv` never carries one (`main.rs` already strips it via `.skip(1)`,
    // and the tests build argv the same way), so `from_args` is the one that
    // does not eat the first real token.
    let mut parser = lexopt::Parser::from_args(argv.iter().map(std::ffi::OsString::from));
    let mut config = PathBuf::from("/etc/signoff.toml");
    let mut sub: Option<String> = None;
    let mut services = Vec::new();
    let mut all = false;
    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Long("config") => config = PathBuf::from(parser.value().map_err(|e| e.to_string())?),
            Long("all") => all = true,
            Long("help") | Short('h') => {
                return Ok(Args {
                    config,
                    cmd: Cmd::Help,
                });
            }
            Long("version") | Short('V') => {
                return Ok(Args {
                    config,
                    cmd: Cmd::Version,
                });
            }
            Value(v) => {
                let v = v.to_string_lossy().into_owned();
                if sub.is_none() {
                    sub = Some(v);
                } else {
                    services.push(v);
                }
            }
            _ => return Err(arg.unexpected().to_string()),
        }
    }
    let selection = |services: Vec<String>, all: bool| -> Result<(Vec<String>, bool), String> {
        if all && !services.is_empty() {
            Err("give either service names or --all, not both".into())
        } else if !all && services.is_empty() {
            Err("give at least one service name, or --all".into())
        } else {
            Ok((services, all))
        }
    };
    let cmd = match sub.as_deref() {
        Some("check") => {
            let (services, all) = selection(services, all)?;
            Cmd::Check { services, all }
        }
        Some("plan") => {
            let (services, all) = selection(services, all)?;
            Cmd::Plan { services, all }
        }
        Some("rules") if services.is_empty() && !all => Cmd::Rules,
        Some("rules") => return Err("rules takes no arguments".into()),
        Some(other) => return Err(format!("unknown command {other:?}")),
        None => return Err("no command".into()),
    };
    Ok(Args { config, cmd })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Args, String> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn check_with_services_and_default_config() {
        let a = p(&["check", "ghostfolio", "kavita"]).unwrap();
        assert_eq!(a.config, std::path::PathBuf::from("/etc/signoff.toml"));
        assert_eq!(
            a.cmd,
            Cmd::Check {
                services: vec!["ghostfolio".into(), "kavita".into()],
                all: false
            }
        );
    }

    #[test]
    fn all_and_config_switches() {
        let a = p(&["--config", "/tmp/s.toml", "check", "--all"]).unwrap();
        assert_eq!(a.config, std::path::PathBuf::from("/tmp/s.toml"));
        assert_eq!(
            a.cmd,
            Cmd::Check {
                services: vec![],
                all: true
            }
        );
        assert_eq!(
            p(&["plan", "--all"]).unwrap().cmd,
            Cmd::Plan {
                services: vec![],
                all: true
            }
        );
    }

    #[test]
    fn check_needs_a_service_or_all() {
        assert!(p(&["check"]).unwrap_err().contains("--all"));
        assert!(p(&["check", "--all", "x"]).unwrap_err().contains("either"));
    }

    #[test]
    fn rules_help_version_and_unknown() {
        assert_eq!(p(&["rules"]).unwrap().cmd, Cmd::Rules);
        assert_eq!(p(&["--help"]).unwrap().cmd, Cmd::Help);
        assert_eq!(p(&["--version"]).unwrap().cmd, Cmd::Version);
        assert!(p(&["frobnicate"]).is_err());
        assert!(p(&["rules", "extra"]).unwrap_err().contains("no arguments"));
        assert!(p(&["rules", "--all"]).unwrap_err().contains("no arguments"));
        assert!(p(&[]).is_err());
    }
}
