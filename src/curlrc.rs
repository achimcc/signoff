//! A curl invocation written as a curl config file (`curl -K -`), so that
//! nothing sensitive — a bearer token, a password — ever appears in argv,
//! which `systemd-run` logs into the guest's journal.

pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Debug, Clone, Default)]
pub struct CurlRc {
    lines: Vec<String>,
}

impl CurlRc {
    pub fn new(url: &str) -> CurlRc {
        CurlRc {
            lines: vec![format!("url = {}", quote(url))],
        }
    }
    fn push(mut self, line: String) -> CurlRc {
        self.lines.push(line);
        self
    }
    pub fn header(self, name: &str, value: &str) -> CurlRc {
        self.push(format!("header = {}", quote(&format!("{name}: {value}"))))
    }
    pub fn request(self, method: &str) -> CurlRc {
        self.push(format!("request = {}", quote(method)))
    }
    pub fn data(self, body: &str) -> CurlRc {
        self.push(format!("data = {}", quote(body)))
    }
    pub fn user(self, user: &str, password: &str) -> CurlRc {
        self.push(format!("user = {}", quote(&format!("{user}:{password}"))))
    }
    pub fn resolve(self, host: &str, port: u16, ip: &str) -> CurlRc {
        self.push(format!(
            "resolve = {}",
            quote(&format!("{host}:{port}:{ip}"))
        ))
    }
    /// Only the HTTP status on stdout.
    pub fn code_only(self) -> CurlRc {
        self.push("silent".into())
            .push("show-error".into())
            .push("output = \"/dev/null\"".into())
            .push("write-out = \"%{http_code}\"".into())
    }
    /// Only the body on stdout; a 4xx/5xx becomes curl exit 22.
    pub fn body_only(self) -> CurlRc {
        self.push("silent".into())
            .push("show-error".into())
            .push("fail".into())
    }
    pub fn max_time(self, secs: u32) -> CurlRc {
        self.push(format!("max-time = {secs}"))
    }
    pub fn render(&self) -> Vec<u8> {
        let mut text = self.lines.join("\n");
        text.push('\n');
        text.into_bytes()
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
        let rc = CurlRc::new("https://ghostfolio.rusty-vault.de/")
            .resolve("ghostfolio.rusty-vault.de", 443, "77.42.71.141")
            .code_only()
            .max_time(15);
        let text = String::from_utf8(rc.render()).unwrap();
        assert_eq!(
            text,
            "url = \"https://ghostfolio.rusty-vault.de/\"\nresolve = \"ghostfolio.rusty-vault.de:443:77.42.71.141\"\nsilent\nshow-error\noutput = \"/dev/null\"\nwrite-out = \"%{http_code}\"\nmax-time = 15\n"
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
