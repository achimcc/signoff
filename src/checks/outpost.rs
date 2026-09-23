//! Behind forward-auth, the identity provider's embedded outpost must
//! carry a proxy provider whose `external_host` is this service — else
//! the login redirect ends in a 404 with `x-authentik-id`, while the
//! service itself answers 200 inside its guest. Matched by
//! `external_host`, not by name: no blueprint is read as text.

use crate::config::{Config, Service};
use crate::curlrc::CurlRc;
use crate::guest;
use crate::runner::Runner;
use crate::verdict::Verdict;
use serde_json::Value;

#[derive(Debug)]
pub struct Auth {
    pub token: String,
}

impl Auth {
    /// A 15-minute API token, minted inside the auth guest. It reaches
    /// curl only as stdin (`curl -K -`), never as an argument.
    pub fn fetch(r: &dyn Runner, cfg: &Config) -> Result<Auth, String> {
        let out = guest::run(r, &cfg.auth_guest, guest::KURZTOKEN, &["signoff"], None)?;
        let token = out.stdout.trim().to_string();
        if out.code != Some(0) || token.is_empty() {
            return Err(format!(
                "authentik-kurztoken in {}: exit {:?}, {}",
                cfg.auth_guest,
                out.code,
                out.stderr
                    .trim()
                    .lines()
                    .next()
                    .unwrap_or("no token on stdout")
            ));
        }
        Ok(Auth { token })
    }
}

fn get(r: &dyn Runner, cfg: &Config, auth: &Auth, path: &str) -> Result<Value, String> {
    let rc = CurlRc::new(&format!("{}{path}", cfg.auth_api))
        .header("Authorization", &format!("Bearer {}", auth.token))
        .body_only()
        .max_time(10);
    let out = guest::curl(r, &cfg.auth_guest, &rc)?;
    if out.code != Some(0) {
        return Err(format!(
            "authentik GET {path}: curl exit {:?}: {}",
            out.code,
            out.stderr.trim().lines().next().unwrap_or("")
        ));
    }
    serde_json::from_str(&out.stdout).map_err(|e| format!("authentik GET {path}: not JSON: {e}"))
}

pub fn providers(r: &dyn Runner, cfg: &Config, auth: &Auth) -> Result<Value, String> {
    get(r, cfg, auth, "/providers/proxy/?page_size=500")
}

pub fn outposts(r: &dyn Runner, cfg: &Config, auth: &Auth) -> Result<Value, String> {
    get(r, cfg, auth, "/outposts/instances/")
}

fn results(v: &Value) -> Option<&Vec<Value>> {
    v.get("results")?.as_array()
}

pub fn judge(providers: &Value, outposts: &Value, host: &str, outpost_name: &str) -> Verdict {
    let Some(list) = results(providers) else {
        return Verdict::CannotMeasure("providers: no `results` array".into());
    };
    let count = providers["pagination"]["count"]
        .as_u64()
        .unwrap_or(list.len() as u64);
    if count != list.len() as u64 {
        return Verdict::CannotMeasure(format!(
            "providers: {count} exist, {} received — list truncated",
            list.len()
        ));
    }
    let wanted = format!("https://{host}");
    let hits: Vec<&Value> = list
        .iter()
        .filter(|p| p["external_host"].as_str() == Some(wanted.as_str()))
        .collect();
    let (pk, name) = match hits.as_slice() {
        [] => return Verdict::Failed(format!("no proxy provider with external_host {wanted}")),
        [one] => (
            one["pk"].as_i64().unwrap_or(-1),
            one["name"].as_str().unwrap_or("?").to_string(),
        ),
        many => {
            let pks: Vec<String> = many.iter().map(|p| p["pk"].to_string()).collect();
            return Verdict::Failed(format!(
                "{} proxy providers with external_host {wanted}: {}",
                many.len(),
                pks.join(", ")
            ));
        }
    };
    let Some(instances) = results(outposts) else {
        return Verdict::CannotMeasure("outposts: no `results` array".into());
    };
    let Some(outpost) = instances
        .iter()
        .find(|o| o["name"].as_str() == Some(outpost_name))
    else {
        return Verdict::CannotMeasure(format!("no outpost named \"{outpost_name}\""));
    };
    let attached = outpost["providers"]
        .as_array()
        .is_some_and(|a| a.iter().any(|p| p.as_i64() == Some(pk)));
    if attached {
        Verdict::Ok(format!(
            "provider {pk} \"{name}\" attached to {outpost_name}"
        ))
    } else {
        Verdict::Failed(format!(
            "provider {pk} \"{name}\" is not attached to outpost \"{outpost_name}\""
        ))
    }
}

pub fn check(r: &dyn Runner, cfg: &Config, s: &Service, auth: &Auth) -> Verdict {
    if !s.forward_auth {
        return Verdict::NotApplicable("no forward_auth".into());
    }
    let (p, o) = match (providers(r, cfg, auth), outposts(r, cfg, auth)) {
        (Ok(p), Ok(o)) => (p, o),
        (Err(e), _) | (_, Err(e)) => return Verdict::CannotMeasure(e),
    };
    judge(&p, &o, &s.host, &cfg.outpost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;
    use crate::runner::{Fake, Output};

    const PROVIDERS: &str = include_str!("../../tests/answers/authentik-providers.json");
    const OUTPOSTS: &str = include_str!("../../tests/answers/authentik-outposts.json");
    const OUTPOST: &str = "authentik Embedded Outpost";

    fn cfg() -> Config {
        parse(include_str!("../../tests/answers/signoff.toml")).unwrap()
    }
    fn out(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }
    fn json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn provider_attached_is_ok_with_pk_and_name() {
        let v = judge(
            &json(PROVIDERS),
            &json(OUTPOSTS),
            "ghostfolio.rusty-vault.de",
            OUTPOST,
        );
        assert_eq!(
            v,
            Verdict::Ok(
                "provider 17 \"Ghostfolio (Forward-Auth)\" attached to authentik Embedded Outpost"
                    .into()
            )
        );
    }

    #[test]
    fn no_provider_for_the_host_is_a_finding() {
        let v = judge(
            &json(PROVIDERS),
            &json(OUTPOSTS),
            "audiobookshelf.rusty-vault.de",
            OUTPOST,
        );
        assert_eq!(
            v,
            Verdict::Failed(
                "no proxy provider with external_host https://audiobookshelf.rusty-vault.de".into()
            )
        );
    }

    #[test]
    fn provider_not_attached_to_the_outpost_is_a_finding() {
        let v = judge(
            &json(PROVIDERS),
            &json(OUTPOSTS),
            "stats.rusty-vault.de",
            OUTPOST,
        );
        assert_eq!(v, Verdict::Failed("provider 9 \"Grafana (Forward-Auth)\" is not attached to outpost \"authentik Embedded Outpost\"".into()));
    }

    #[test]
    fn two_providers_for_one_host_is_a_finding() {
        let mut p = json(PROVIDERS);
        p["results"].as_array_mut().unwrap().push(serde_json::json!({"pk": 40, "name": "Ghostfolio (Kopie)", "external_host": "https://ghostfolio.rusty-vault.de"}));
        p["pagination"]["count"] = serde_json::json!(4);
        let v = judge(&p, &json(OUTPOSTS), "ghostfolio.rusty-vault.de", OUTPOST);
        assert_eq!(
            v,
            Verdict::Failed(
                "2 proxy providers with external_host https://ghostfolio.rusty-vault.de: 17, 40"
                    .into()
            )
        );
    }

    #[test]
    fn truncated_list_or_missing_outpost_is_cannot_measure() {
        let mut p = json(PROVIDERS);
        p["pagination"]["count"] = serde_json::json!(50);
        assert!(matches!(
            judge(&p, &json(OUTPOSTS), "ghostfolio.rusty-vault.de", OUTPOST),
            Verdict::CannotMeasure(_)
        ));
        assert!(matches!(
            judge(
                &json(PROVIDERS),
                &json(OUTPOSTS),
                "ghostfolio.rusty-vault.de",
                "Nope"
            ),
            Verdict::CannotMeasure(_)
        ));
    }

    #[test]
    fn token_travels_via_stdin_only() {
        let c = cfg();
        let fake = Fake::new()
            .on(
                "systemd-run",
                "authentik-kurztoken signoff",
                out(0, "ak-secret-token\n", ""),
            )
            .on("systemd-run", "curl -K -", out(0, PROVIDERS, ""));
        let auth = Auth::fetch(&fake, &c).unwrap();
        providers(&fake, &c, &auth).unwrap();
        for (_, argv, _) in fake.calls() {
            assert!(
                !argv.join(" ").contains("ak-secret-token"),
                "token in argv: {argv:?}"
            );
        }
        let stdin = fake.calls()[1].2.clone().unwrap();
        let text = String::from_utf8(stdin).unwrap();
        assert!(text.contains("header = \"Authorization: Bearer ak-secret-token\""));
        assert!(
            text.contains("url = \"http://127.0.0.1:9000/api/v3/providers/proxy/?page_size=500\"")
        );
        assert!(text.contains("\nfail\n"));
    }

    #[test]
    fn token_failure_and_http_error_are_errors_not_findings() {
        let c = cfg();
        let silent = Fake::new().on("systemd-run", "authentik-kurztoken", out(0, "", ""));
        assert!(
            Auth::fetch(&silent, &c)
                .unwrap_err()
                .contains("authentik-kurztoken")
        );
        let auth = Auth { token: "t".into() };
        let denied = Fake::new().on(
            "systemd-run",
            "curl -K -",
            out(22, "", "curl: (22) The requested URL returned error: 403"),
        );
        assert!(providers(&denied, &c, &auth).unwrap_err().contains("403"));
    }

    #[test]
    fn check_skips_services_without_forward_auth() {
        let c = cfg();
        let fake = Fake::new();
        let auth = Auth { token: "t".into() };
        assert_eq!(
            check(&fake, &c, c.service("radarr").unwrap(), &auth),
            Verdict::NotApplicable("no forward_auth".into())
        );
        assert!(fake.calls().is_empty());
    }
}
