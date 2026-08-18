/// Strips terminal escapes and replaces control characters so
/// process-controlled strings cannot break a table or hijack the TTY.
/// JSON output keeps the original bytes.
#[must_use]
pub fn sanitize_display(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let stripped = strip_escapes(s);
    let mut out = String::with_capacity(stripped.len());
    for c in stripped.chars() {
        let u = c as u32;
        if u < 32 || u == 127 || (0x80..=0x9F).contains(&u) {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

/// Helper for CLI table formatting that displays `-` if empty after sanitizing.
#[must_use]
pub fn display_cell(s: &str) -> String {
    let sanitized = sanitize_display(s);
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Helper to display `-` for an empty string.
#[must_use]
pub fn dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

fn strip_escapes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != 0x1b {
            out.push(bytes[i]);
            i += 1;
            continue;
        }

        if i + 1 >= bytes.len() {
            break;
        }

        match bytes[i + 1] {
            b'[' => {
                // CSI
                i = skip_until(bytes, i + 2, |c| (0x40..=0x7e).contains(&c));
            }
            b']' => {
                // OSC
                i = skip_osc(bytes, i + 2);
            }
            b'P' | b'X' | b'^' | b'_' => {
                // DCS / SOS / PM / APC
                i = skip_st(bytes, i + 2);
            }
            b'\\' => {
                // stray ST
                i += 2;
            }
            _ => {
                // ESC Fe or ESC + intermediate
                let mut j = i + 2;
                while j < bytes.len() && (0x20..=0x2f).contains(&bytes[j]) {
                    j += 1;
                }
                if j < bytes.len() && (0x30..=0x7e).contains(&bytes[j]) {
                    i = j + 1;
                } else {
                    i = j;
                }
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn skip_until<F>(bytes: &[u8], mut i: usize, done: F) -> usize
where
    F: Fn(u8) -> bool,
{
    while i < bytes.len() {
        let c = bytes[i];
        i += 1;
        if done(c) {
            break;
        }
    }
    i
}

fn skip_osc(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if bytes[i] == 0x07 {
            // BEL
            return i + 1;
        }
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
            return i + 2;
        }
        i += 1;
    }
    i
}

fn skip_st(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
            return i + 2;
        }
        i += 1;
    }
    i
}
