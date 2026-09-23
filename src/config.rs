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
        if let Some(f) = &s.factory_login {
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
    fn missing_top_level_field_names_it() {
        let t = EXAMPLE.replace("resolver = \"1.1.1.1\"\n", "");
        assert!(parse(&t).unwrap_err().contains("resolver"));
    }
}
