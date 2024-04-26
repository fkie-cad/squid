pub const EWE_SOURCE: &str = "EWE_SOURCE";

pub fn is_hexchar(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || (b'A'..=b'F').contains(&c)
}

pub fn is_whitespace(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

pub fn is_jump_target(label: &[u8]) -> bool {
    if label[0] != b'L' {
        return false;
    }

    /*
    let mut i = 1;

    while i < label.len() {
        if !is_decimal(label[i]) {
            return false;
        } else {
            i += 1;
        }
    }
    */

    true
}

pub fn is_digit_label(label: &[u8]) -> bool {
    label.iter().all(|c| c.is_ascii_digit())
}

pub fn is_debug_label(label: &[u8]) -> bool {
    label.starts_with(b"LFB") || label.starts_with(b"LFE") || label.starts_with(b"LBB") || label.starts_with(b"LBE") || label.starts_with(b"LVL")
}

//TODO: use directive struct
pub fn parse_section_directive(line: &[u8], has_sub: bool) -> (&str, Option<&str>) {
    /* Parse name */
    let mut name_start = 0;

    while name_start < line.len() && !is_whitespace(line[name_start]) {
        name_start += 1;
    }

    while name_start < line.len() && is_whitespace(line[name_start]) {
        name_start += 1;
    }

    if name_start < line.len() && line[name_start] == b'"' {
        name_start += 1;
    }

    let mut name_end = name_start;

    while name_end < line.len() && line[name_end] != b',' {
        name_end += 1;
    }

    /* Parse flags */
    let mut flags_start = name_end + 1;

    if name_end < line.len() && line[name_end - 1] == b'"' {
        name_end -= 1;
    }

    /* skip subsection if necessary */
    if has_sub {
        while flags_start < line.len() && is_whitespace(line[flags_start]) {
            flags_start += 1;
        }

        let mut tmp = flags_start;

        while tmp < line.len() && line[tmp].is_ascii_digit() {
            tmp += 1;
        }

        if tmp > flags_start {
            flags_start = tmp + 1;
        }
    }

    while flags_start < line.len() && is_whitespace(line[flags_start]) {
        flags_start += 1;
    }

    if flags_start < line.len() {
        assert_eq!(line[flags_start], b'"', "Failed to parse section directive (has_sub={}): {}", has_sub, std::str::from_utf8(line).unwrap());
        flags_start += 1;
    }

    let mut flags_end = flags_start;

    while flags_end < line.len() && line[flags_end] != b'"' {
        flags_end += 1;
    }

    /* Return substrings */
    let name = std::str::from_utf8(&line[name_start..name_end]).unwrap();
    let flags = if flags_start < line.len() { Some(std::str::from_utf8(&line[flags_start..flags_end]).unwrap()) } else { None };

    (name, flags)
}

/// Make sure that there is only one statement / label per line.
pub fn separate_statements(input: &[u8], filename: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut i = 0;
    let mut in_quote = false;
    let mut escaped = false;

    if !input.starts_with(b".title") {
        let filename = std::path::Path::new(filename);
        let filename = filename.canonicalize().unwrap();
        let title = format!(".title \"{EWE_SOURCE}={}\"\n", filename.display());
        output.extend_from_slice(title.as_bytes());
    }

    while i < input.len() {
        // Check if we are in quote
        if input[i] == b'"' && !escaped {
            in_quote = !in_quote;
        }

        // Skip comments
        while !in_quote && i < input.len() {
            if input[i] == b'#' {
                while i < input.len() && input[i] != b'\n' {
                    i += 1;
                }
            } else if input[i] == b'/' && input.get(i + 1) == Some(&b'*') {
                i += 2;
                while i + 1 < input.len() && (input[i] != b'*' || input[i + 1] != b'/') {
                    i += 1;
                }
                i += 2;
                output.push(b' ');
            } else {
                break;
            }
        }

        if i < input.len() {
            // Copy byte
            escaped = in_quote && input[i] == b'\\' && !escaped;
            output.push(input[i]);

            // Insert whitespaces after labels and instructions
            if !in_quote {
                match input[i] {
                    b';' | b':' => output.push(b'\n'),
                    _ => {},
                }
            }
        }

        i += 1;
    }

    output
}

#[derive(Debug)]
pub struct Directive<'a> {
    //name: &'a str,
    args: Vec<&'a str>,
}

impl<'a> Directive<'a> {
    pub fn new<const SEP: u8>(d: &'a [u8]) -> Self {
        let directive = std::str::from_utf8(d).unwrap();
        assert_eq!(d[0], b'.');

        /* Parse directive name */
        let mut i = 1;

        while i < d.len() && !is_whitespace(d[i]) {
            i += 1;
        }

        //let name = &directive[1..i];

        /* Parse arguments */
        let mut args = Vec::new();

        while i < d.len() {
            /* Skip whitespace */
            while i < d.len() && is_whitespace(d[i]) {
                i += 1;
            }

            let arg_start = i;
            let mut in_quote = false;
            let mut escaped = false;

            /* Search the next comma that is not inside a quote */
            while i < d.len() && (in_quote || d[i] != SEP) {
                if !escaped && d[i] == b'"' {
                    in_quote = !in_quote;
                }
                i += 1;
                escaped = in_quote && d[i] == b'\\' && !escaped;
            }

            /* Trim trailing whitespace */
            let mut arg_end = i;
            while arg_end > arg_start && is_whitespace(d[arg_end - 1]) {
                arg_end -= 1;
            }

            /* Found arg */
            if arg_start < d.len() && arg_end > arg_start {
                args.push(&directive[arg_start..arg_end]);
            }

            i += 1;
        }

        Self {
            //name,
            args,
        }
    }

    pub fn args(&self) -> &[&'a str] {
        &self.args
    }
}

pub fn is_assignment(d: &[u8]) -> bool {
    let mut i = 0;

    while i < d.len() && d[i] != b'=' {
        if d[i] == b'"' {
            return false;
        }
        i += 1;
    }

    if i >= d.len() {
        return false;
    } else {
        i += 1;
    }

    while i < d.len() && d[i] != b'=' {
        if d[i] == b'"' {
            return false;
        }
        i += 1;
    }

    i == d.len()
}

pub fn parse_assignment(d: &[u8]) -> Option<(&str, &str)> {
    let mut i = 0;

    /* Skip whitespace */
    while i < d.len() && is_whitespace(d[i]) {
        i += 1;
    }

    /* Parse lhs */
    let lhs_start = i;

    while i < d.len() && d[i] != b'=' {
        i += 1;
    }

    let mut lhs_end = i;

    while lhs_end > lhs_start && is_whitespace(d[lhs_end - 1]) {
        lhs_end -= 1;
    }

    /* Parse rhs */
    i += 1;

    while i < d.len() && is_whitespace(d[i]) {
        i += 1;
    }

    let mut rhs_end = d.len();

    while rhs_end > i && is_whitespace(d[rhs_end - 1]) {
        rhs_end -= 1;
    }

    let lhs = std::str::from_utf8(&d[lhs_start..lhs_end]).unwrap();
    let rhs = std::str::from_utf8(&d[i..rhs_end]).unwrap();

    if !lhs.is_empty() && !rhs.is_empty() {
        Some((lhs, rhs))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directive_parser() {
        let d = Directive::new::<b','>(b".set    gnu_get_libc_release,__gnu_get_libc_release");
        println!("{:?}", d);

        let d = Directive::new::<b' '>(b".loc 1 59 1 is_stmt 1");
        println!("{:?}", d);

        let d = Directive::new::<b','>(b".cfi_startproc");
        println!("{:?}", d);

        let d = Directive::new::<b','>(b".section        .rodata.str1.8,\"aMS\",@progbits,1");
        println!("{:?}", d);

        let d = Directive::new::<b','>(b".ascii  \", right (C) 2021 Free Software Foundation, Inc.\\nThis is \\\"free\\\" \"");
        println!("{:?}", d);
    }
}
