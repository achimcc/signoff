//! A curl invocation written as a curl config file (`curl -K -`), so that
//! nothing sensitive — a bearer token, a password — ever appears in argv,
//! which `systemd-run` logs into the guest's journal.
//!
//! Since 0.5.2 the syntax comes from vantage (`vantage::curlrc::CurlRc`):
//! the quoting function existed there, in gast-pruefung and here, byte for
//! byte the same. What stays here are signoff's three idioms — only the
//! status, body then status, body only.

pub use vantage::curlrc::quote;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CurlRc {
    rc: vantage::curlrc::CurlRc,
}

impl CurlRc {
    pub fn new(url: &str) -> CurlRc {
        CurlRc {
            rc: vantage::curlrc::CurlRc::new(url),
        }
    }
    fn map(self, f: impl FnOnce(vantage::curlrc::CurlRc) -> vantage::curlrc::CurlRc) -> CurlRc {
        CurlRc { rc: f(self.rc) }
    }
    pub fn header(self, name: &str, value: &str) -> CurlRc {
        self.map(|rc| rc.header(name, value))
    }
    pub fn request(self, method: &str) -> CurlRc {
        self.map(|rc| rc.request(method))
    }
    pub fn data(self, body: &str) -> CurlRc {
        self.map(|rc| rc.data(body))
    }
    pub fn user(self, user: &str, password: &str) -> CurlRc {
        self.map(|rc| rc.user(user, password))
    }
    pub fn resolve(self, host: &str, port: u16, ip: &str) -> CurlRc {
        self.map(|rc| rc.resolve(host, port, ip))
    }
    /// Only the HTTP status on stdout.
    pub fn code_only(self) -> CurlRc {
        self.map(|rc| {
            rc.silent_show_error()
                .discard_body()
                .write_out("%{http_code}")
        })
    }
    /// The body on stdout, then the HTTP status on a last line of its own —
    /// for a probe whose answer is decided by what the body says. The
    /// caller's `Limits` cap how much body is read.
    pub fn body_then_code(self) -> CurlRc {
        self.map(|rc| rc.silent_show_error().write_out("\n%{http_code}"))
    }
    /// Only the body on stdout; a 4xx/5xx becomes curl exit 22.
    pub fn body_only(self) -> CurlRc {
        self.map(|rc| rc.silent_show_error().fail())
    }
    pub fn max_time(self, secs: u32) -> CurlRc {
        self.map(|rc| rc.max_time(secs))
    }
    pub fn render(&self) -> Vec<u8> {
        self.rc.render().into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_escapes_backslash_quote_and_newline() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quote("x\ny"), "\"x\\ny\"");
    }

    #[test]
    fn renders_one_option_per_line_in_curl_config_syntax() {
        let rc = CurlRc::new("https://ghostfolio.rusty-vault.de:8443/")
            .resolve("ghostfolio.rusty-vault.de", 8443, "10.0.20.11")
            .code_only()
            .max_time(15);
        let text = String::from_utf8(rc.render()).unwrap();
        assert_eq!(
            text,
            "url = \"https://ghostfolio.rusty-vault.de:8443/\"\nresolve = \"ghostfolio.rusty-vault.de:8443:10.0.20.11\"\nsilent\nshow-error\noutput = \"/dev/null\"\nwrite-out = \"%{http_code}\"\nmax-time = 15\n"
        );
    }

    #[test]
    fn body_then_code_keeps_the_body_and_ends_with_the_status() {
        let rc = CurlRc::new("http://10.0.10.10:8080/api/v2/auth/login").body_then_code();
        let text = String::from_utf8(rc.render()).unwrap();
        assert!(!text.contains("output ="), "{text}");
        assert!(
            text.ends_with("silent\nshow-error\nwrite-out = \"\\n%{http_code}\"\n"),
            "{text}"
        );
    }

    #[test]
    fn header_request_data_user_and_body_only() {
        let rc = CurlRc::new("http://127.0.0.1:9000/api/v3/providers/proxy/")
            .header("Authorization", "Bearer abc")
            .request("POST")
            .data("a=1&b=2")
            .user("admin", "admin")
            .body_only();
        let text = String::from_utf8(rc.render()).unwrap();
        assert!(text.contains("header = \"Authorization: Bearer abc\"\n"));
        assert!(text.contains("request = \"POST\"\n"));
        assert!(text.contains("data = \"a=1&b=2\"\n"));
        assert!(text.contains("user = \"admin:admin\"\n"));
        assert!(text.ends_with("silent\nshow-error\nfail\n"));
    }
}
