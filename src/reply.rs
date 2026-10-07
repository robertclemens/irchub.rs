//! Admin console replies as records — the builder (hub_reply.c).
//!
//! Every `CMD_ADMIN_*` reply is UTF-8 text, one record per line:
//!
//! ```text
//! ok|<code>[|k=v…]                       or
//! err|<code>|msg=<text>[|hint=<text>][|k=v…]
//! <type>|k=v|k=v…                        (data records, any number)
//! more|n=<count>                         (records that did not fit)
//! ```
//!
//! `<code>` is a dotted slug that never changes once shipped.  Values escape
//! `%` `|` `\n` `\r` as `%25 %7C %0A %0D` and nothing else; times are Unix
//! seconds, sizes bytes, booleans 0/1, lists `,`-separated, and a missing
//! value is an absent key.  The console renders them (`console::fmt`); the C
//! hub's hub_reply.c builds the same bytes.

/// A reply never grows past this; records past it are counted in `more|`.
pub const CONSOLE_REPLY_MAX: usize = 256 * 1024;
/// Room kept for the `more|` record once the reply is full.
const REPLY_MORE_RESERVE: usize = 32;

#[derive(Default)]
pub struct Reply {
    /// Committed records, '\n'-separated.
    p: String,
    /// The record being built.
    line: String,
    in_line: bool,
    /// Records that did not fit.
    dropped: usize,
}

impl Reply {
    pub fn new() -> Reply {
        Reply::default()
    }

    /// Move the finished record into the reply, or count it as dropped.
    fn commit(&mut self) {
        if !self.in_line {
            return;
        }
        self.in_line = false;
        let need = self.p.len() + usize::from(!self.p.is_empty()) + self.line.len();
        if self.dropped > 0 || need > CONSOLE_REPLY_MAX - REPLY_MORE_RESERVE {
            self.dropped += 1;
            self.line.clear();
            return;
        }
        if !self.p.is_empty() {
            self.p.push('\n');
        }
        self.p.push_str(&self.line);
        self.line.clear();
    }

    fn start(&mut self, ty: &str) {
        self.commit();
        self.in_line = true;
        self.line.clear();
        self.line.push_str(ty);
    }

    /// Result line (always the first record).
    pub fn ok(&mut self, code: &str) {
        self.start("ok|");
        self.line.push_str(code);
    }

    pub fn err(&mut self, code: &str, msg: Option<&str>, hint: Option<&str>) {
        self.start("err|");
        self.line.push_str(code);
        self.kv_opt("msg", msg);
        self.kv_opt("hint", hint);
    }

    /// Start a data record of this type; the k=v calls append to it.
    pub fn rec(&mut self, ty: &str) {
        self.start(ty);
    }

    /// key=value on the current record (escaped).
    pub fn kv(&mut self, key: &str, val: &str) {
        if !self.in_line {
            return;
        }
        self.line.push('|');
        self.line.push_str(key);
        self.line.push('=');
        for c in val.chars() {
            match c {
                '%' => self.line.push_str("%25"),
                '|' => self.line.push_str("%7C"),
                '\n' => self.line.push_str("%0A"),
                '\r' => self.line.push_str("%0D"),
                '\0' => break,
                _ => self.line.push(c),
            }
        }
    }

    pub fn kv_opt(&mut self, key: &str, val: Option<&str>) {
        if let Some(v) = val {
            self.kv(key, v);
        }
    }

    pub fn kvi(&mut self, key: &str, v: i64) {
        self.kv(key, &v.to_string());
    }

    pub fn kvu(&mut self, key: &str, v: u64) {
        self.kv(key, &v.to_string());
    }

    pub fn kvb(&mut self, key: &str, v: bool) {
        self.kv(key, if v { "1" } else { "0" });
    }

    /// The finished text, with a `more|` record when needed.
    pub fn text(&mut self) -> &str {
        self.commit();
        if self.dropped > 0 {
            let m = format!(
                "{}more|n={}",
                if self.p.is_empty() { "" } else { "\n" },
                self.dropped
            );
            self.dropped = 0;
            self.p.push_str(&m);
        }
        &self.p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_overflows() {
        let mut r = Reply::new();
        r.ok("x.y");
        r.kv("a", "1|2%\n\r=");
        r.rec("t");
        r.kvi("n", -3);
        assert_eq!(r.text(), "ok|x.y|a=1%7C2%25%0A%0D=\nt|n=-3");
        let mut r = Reply::new();
        r.ok("big");
        for _ in 0..30000 {
            r.rec("rec");
            r.kv("v", "0123456789");
        }
        let t = r.text().to_string();
        assert!(t.len() <= CONSOLE_REPLY_MAX);
        assert!(t.ends_with(&format!("more|n={}", 30000 - (t.lines().count() - 2))));
    }
}
