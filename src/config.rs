//! `/etc/signoff.toml`: data rendered by the host's Nix configuration.
//! Parsed with serde, then validated: the file is data, the rules about
//! the data live here.

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub zone: String,
    pub resolver: String,
    pub vps_v4: String,
    pub vps_v6: String,
    pub caddy_guest: String,
    pub auth_guest: String,
    pub auth_api: String,
    pub outpost: String,
    pub rustic_profile: String,
    pub snapshot_max_age_hours: u64,
    /// Strict mode: a service with neither a `factory_login` probe nor a
    /// `no_factory_login` reason is a finding (`failed`, exit 1) instead of
    /// the hint `undeclared`. Off by default.
    #[serde(default)]
    pub undeclared_is_failure: bool,
    #[serde(default)]
    pub service: Vec<Service>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub key: String,
    pub host: String,
    pub guest: String,
    pub public: bool,
    pub backend: Option<String>,
    pub backend_guest: Option<String>,
    pub forward_auth: bool,
    pub dataset: String,
    pub factory_login: Option<FactoryLogin>,
    /// The written-down exception: this service ships without a factory
    /// account (or its local login is switched off), and this is why.
    /// Excludes `factory_login` — a service has a probe or a reason.
    pub no_factory_login: Option<String>,
}

fn get() -> String {
    "GET".into()
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FactoryLogin {
    #[serde(default = "get")]
    pub method: String,
    pub path: String,
    pub content_type: Option<String>,
    pub body: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub reject: Vec<u16>,
    /// Some services answer a wrong login with HTTP 200 and a text
    /// (qBittorrent: `Fails.`). When set, a response only counts as rejected
    /// if its status is in `reject` AND its body contains this substring.
    pub reject_body: Option<String>,
}

impl Service {
    pub fn backend_port(&self) -> Option<u16> {
        self.backend.as_ref()?.rsplit_once(':')?.1.parse().ok()
    }
}

impl Config {
    pub fn service(&self, key: &str) -> Option<&Service> {
        self.service.iter().find(|s| s.key == key)
    }
}

pub fn parse(text: &str) -> Result<Config, String> {
    let c: Config = toml::from_str(text).map_err(|e| format!("config: {e}"))?;
    validate(&c)?;
    Ok(c)
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text)
}

fn validate(c: &Config) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for s in &c.service {
        if !seen.insert(&s.key) {
            return Err(format!("config: service key {:?} appears twice", s.key));
        }
        if let Some(b) = &s.backend {
            let ok = b.rsplit_once(':').is_some_and(|(ip, port)| {
                port.parse::<u16>().is_ok()
                    && ip.split('.').count() == 4
                    && ip.split('.').all(|o| o.parse::<u8>().is_ok())
            });
            if !ok {
                return Err(format!(
                    "config: service {:?}: backend {b:?} is not ip:port",
                    s.key
                ));
            }
        }
        if let Some(reason) = &s.no_factory_login {
            if s.factory_login.is_some() {
                return Err(format!(
                    "config: service {:?}: no_factory_login and factory_login are both declared — a service has a probe or a reason, not both",
                    s.key
                ));
            }
            if reason.trim().is_empty() {
                return Err(format!(
                    "config: service {:?}: no_factory_login needs a reason, not an empty string",
                    s.key
                ));
            }
        }
        if let Some(f) = &s.factory_login {
            // An empty substring is contained in every body: the check would
            // silently be the status check again.
            if f.reject_body.as_deref().is_some_and(str::is_empty) {
                return Err(format!(
                    "config: service {:?}: factory_login.reject_body must not be empty",
                    s.key
                ));
            }
            if f.reject.is_empty() {
                return Err(format!(
                    "config: service {:?}: factory_login.reject must list at least one status",
                    s.key
                ));
            }
            let basic = f.user.is_some() || f.password.is_some();
            if basic && f.body.is_some() {
                return Err(format!(
                    "config: service {:?}: factory_login takes either body or user/password, not both",
                    s.key
                ));
            }
            if f.user.is_some() != f.password.is_some() {
                return Err(format!(
                    "config: service {:?}: factory_login needs user and password together",
                    s.key
                ));
            }
            if !f.path.starts_with('/') {
                return Err(format!(
                    "config: service {:?}: factory_login.path must start with /",
                    s.key
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../tests/answers/signoff.toml");

    #[test]
    fn parses_the_example() {
        let c = parse(EXAMPLE).unwrap();
        assert_eq!(c.zone, "rusty-vault.de");
        assert_eq!(c.snapshot_max_age_hours, 48);
        assert_eq!(c.service.len(), 3);
        let g = c.service("ghostfolio").unwrap();
        assert_eq!(g.backend_port(), Some(3333));
        assert_eq!(g.backend_guest.as_deref(), Some("fin-01"));
        let fl = g.factory_login.as_ref().unwrap();
        assert_eq!(fl.method, "POST");
        assert_eq!(fl.reject, vec![401, 403]);
        assert!(c.service("start").unwrap().backend.is_none());
        assert!(c.service("nope").is_none());
    }

    #[test]
    fn factory_login_method_defaults_to_get() {
        let t = EXAMPLE.replace("method = \"POST\"\n", "");
        let c = parse(&t).unwrap();
        assert_eq!(
            c.service("ghostfolio")
                .unwrap()
                .factory_login
                .as_ref()
                .unwrap()
                .method,
            "GET"
        );
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let t = format!(
            "{EXAMPLE}\n[[service]]\nkey = \"radarr\"\nhost = \"x\"\nguest = \"g\"\npublic = false\nforward_auth = false\ndataset = \"d\"\n"
        );
        let e = parse(&t).unwrap_err();
        assert!(e.contains("radarr"), "{e}");
        assert!(e.contains("twice"), "{e}");
    }

    #[test]
    fn backend_must_be_ip_colon_port() {
        let t = EXAMPLE.replace("backend = \"10.0.190.10:3333\"", "backend = \"fin-01\"");
        let e = parse(&t).unwrap_err();
        assert!(e.contains("backend"), "{e}");
    }

    #[test]
    fn factory_login_needs_reject_codes_and_one_credential_form() {
        let t = EXAMPLE.replace("reject = [401, 403]", "reject = []");
        assert!(parse(&t).unwrap_err().contains("reject"));
        let t = EXAMPLE.replace(
            "body = \"username=changeme%40example.com&password=MyPassword\"",
            "body = \"x\"\nuser = \"admin\"\npassword = \"admin\"",
        );
        assert!(parse(&t).unwrap_err().contains("either"));
    }

    #[test]
    fn no_factory_login_is_a_reason_and_excludes_a_probe() {
        let radarr = "dataset = \"rpool/guests/media-01\"\n";
        let t = EXAMPLE.replace(
            radarr,
            &format!("{radarr}no_factory_login = \"local login is disabled, OIDC only\"\n"),
        );
        let c = parse(&t).unwrap();
        assert_eq!(
            c.service("radarr").unwrap().no_factory_login.as_deref(),
            Some("local login is disabled, OIDC only")
        );
        assert!(c.service("ghostfolio").unwrap().no_factory_login.is_none());

        // A reason next to a probe: one of the two is wrong.
        let ghostfolio = "dataset = \"rpool/guests/fin-01\"\n";
        let t = EXAMPLE.replace(
            ghostfolio,
            &format!("{ghostfolio}no_factory_login = \"no account\"\n"),
        );
        let e = parse(&t).unwrap_err();
        assert!(e.contains("ghostfolio"), "{e}");
        assert!(e.contains("both declared"), "{e}");

        for empty in ["", "   ", "\\t"] {
            let t = EXAMPLE.replace(radarr, &format!("{radarr}no_factory_login = \"{empty}\"\n"));
            let e = parse(&t).unwrap_err();
            assert!(e.contains("radarr"), "{e}");
            assert!(e.contains("needs a reason"), "{e}");
        }
    }

    #[test]
    fn reject_body_is_optional_and_never_empty() {
        let c = parse(EXAMPLE).unwrap();
        let fl = c.service("ghostfolio").unwrap().factory_login.clone();
        assert_eq!(fl.unwrap().reject_body, None);
        let t = EXAMPLE.replace(
            "reject = [401, 403]",
            "reject = [200]\nreject_body = \"Fails.\"",
        );
        let c = parse(&t).unwrap();
        let fl = c.service("ghostfolio").unwrap().factory_login.clone();
        assert_eq!(fl.unwrap().reject_body.as_deref(), Some("Fails."));
        let t = EXAMPLE.replace("reject = [401, 403]", "reject = [200]\nreject_body = \"\"");
        assert!(parse(&t).unwrap_err().contains("reject_body"));
    }

    #[test]
    fn undeclared_is_failure_defaults_to_false() {
        assert!(!parse(EXAMPLE).unwrap().undeclared_is_failure);
        let t = format!("undeclared_is_failure = true\n{EXAMPLE}");
        assert!(parse(&t).unwrap().undeclared_is_failure);
    }

    #[test]
    fn missing_top_level_field_names_it() {
        let t = EXAMPLE.replace("resolver = \"1.1.1.1\"\n", "");
        assert!(parse(&t).unwrap_err().contains("resolver"));
    }
}
