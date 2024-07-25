/*
A line can be:
    - empty
    - \fGAS LISTING
    - EWE_SOURCE=
or one of the below:
  34 0000 130101FF              addi    sp,sp,-16
  40      E7800000
  32                    f:
  147
 22059 740c 13000000 	>  .align 4
 22059              	>
*/

use std::{
    collections::{
        HashMap,
        HashSet,
    },
    path::{
        Path,
        PathBuf,
    },
};

use crate::asm::{
    is_assignment,
    is_debug_label,
    is_digit_label,
    is_hexchar,
    is_jump_target,
    is_whitespace,
    parse_assignment,
    parse_section_directive,
    Directive,
    EWE_SOURCE,
};

pub const EXTENSION: &str = "ewe";

#[derive(Debug, PartialEq)]
pub struct ListingFunction {
    names: Vec<String>,
    bb: Vec<usize>,
    path: PathBuf,
    size: usize,
}

impl ListingFunction {
    fn new(name: String, filename: &str) -> Self {
        Self {
            names: vec![name],
            bb: vec![0],
            path: PathBuf::from(filename),
            size: 0,
        }
    }

    fn finalize(&mut self) {
        assert!(!self.names.is_empty());
        self.bb.retain(|x| *x > 0);
        assert!(!self.bb.is_empty());

        let mut size = 0;

        for bb in &self.bb {
            size += *bb;
        }

        self.size = size;
    }

    fn mark_name_default(&mut self, idx: usize) {
        if let Some((prefix, _)) = self.names[idx].split_once('@') {
            self.names.push(prefix.to_string());
        }
    }

    fn add_name(&mut self, name: String) {
        match self.names.binary_search(&name) {
            Ok(_) => {},
            Err(pos) => self.names.insert(pos, name),
        }
    }

    fn has_name(&self, name: &str) -> bool {
        self.names.iter().any(|x| x.as_str() == name)
    }

    fn has_name_any_version(&self, name: &str) -> bool {
        self.names.iter().any(|x| x.as_str() == name || (x.starts_with(name) && x.chars().nth(name.len()) == Some('@')))
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    pub fn boundaries(&self) -> &[usize] {
        &self.bb
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

struct FunctionBuilder<'a> {
    functions: Vec<ListingFunction>,
    current_functions: Vec<ListingFunction>,
    filename: &'a str,
    aliases: Vec<(&'a str, &'a str)>,
}

impl<'a> FunctionBuilder<'a> {
    fn new() -> Self {
        Self {
            functions: Vec::new(),
            current_functions: Vec::new(),
            filename: "",
            aliases: Vec::new(),
        }
    }

    fn start_function(&mut self, name: String) {
        if let Some(last) = self.current_functions.last_mut() {
            if last.bb.len() == 1 && last.bb[0] == 0 {
                last.add_name(name);
                return;
            }
        }

        #[cfg(test)]
        println!("Start function: {}", name);

        self.current_functions.push(ListingFunction::new(name, self.filename));
    }

    fn start_bb(&mut self) {
        if let Some(func) = self.current_functions.last_mut() {
            func.bb.push(0);
        }

        #[cfg(test)]
        println!("Start BB");
    }

    fn feed_bytes(&mut self, bytes: usize) {
        *self.current_functions.last_mut().unwrap().bb.last_mut().unwrap() += bytes;

        #[cfg(test)]
        println!("Feed bytes: {}", bytes);
    }

    fn alias(&mut self, name: &'a str, new_name: &'a str) {
        self.aliases.push((name, new_name));
    }

    fn feed_elem(&mut self, elem: ListingElem<'a>) {
        match elem {
            ListingElem::Assembly(bytes, directive) => {
                if let Some(bytes) = bytes {
                    assert_eq!(bytes.len() % 2, 0);
                    self.feed_bytes(bytes.len() / 2);
                } else if directive[directive.len() - 1] == b':' {
                    let directive = &directive[..directive.len() - 1];

                    if directive[0] != b'.' {
                        if is_digit_label(directive) {
                            self.start_bb();
                        } else {
                            let func = std::str::from_utf8(directive).unwrap();
                            self.start_function(func.to_string());
                        }
                    } else {
                        let directive = &directive[1..];

                        if is_jump_target(directive) && !is_debug_label(directive) {
                            self.start_bb();
                        } else {
                            assert!(is_debug_label(directive), "Unknown label: {:?}", std::str::from_utf8(directive));
                        }
                    }
                } else if directive.starts_with(b".set") {
                    let directive = Directive::new::<b','>(directive);
                    self.alias(directive.args()[1], directive.args()[0]);
                } else if directive.starts_with(b".symver") {
                    let directive = Directive::new::<b','>(directive);
                    let name = directive.args()[0];
                    let new_name = directive.args()[1];

                    if new_name.contains("@@@") {
                        panic!(".symver with @@@ is not supported");
                    }

                    self.alias(name, new_name);
                } else if is_assignment(directive) {
                    if let Some((lhs, rhs)) = parse_assignment(directive) {
                        self.alias(rhs, lhs);
                    }
                }
            },
            ListingElem::Continuation(bytes) => {
                assert_eq!(bytes.len() % 2, 0);
                self.feed_bytes(bytes.len() / 2);
            },
            _ => unreachable!(),
        }
    }

    fn apply_aliases(&mut self) {
        let mut mask = vec![false; self.aliases.len()];

        loop {
            let mut changed = false;

            for (i, flag) in mask.iter_mut().enumerate() {
                if *flag {
                    continue;
                }

                let (name, new_name) = self.aliases[i];
                let mut found = false;

                for func in &mut self.current_functions {
                    if func.has_name(name) {
                        func.add_name(new_name.to_string());
                        found = true;
                    }
                }

                if found {
                    *flag = true;
                    changed = true;
                }
            }

            if !changed {
                break;
            }
        }

        self.aliases.clear();
    }

    fn flush(&mut self) {
        self.apply_aliases();

        for func in self.current_functions.drain(..) {
            if !self.functions.contains(&func) {
                self.functions.push(func);
            }
        }
    }

    fn feed_filename(&mut self, filename: &'a [u8]) {
        let filename = std::str::from_utf8(filename).unwrap();

        if self.filename != filename {
            self.flush();
            self.filename = filename;
        }
    }

    fn find_default_versions(&mut self) -> Vec<(usize, usize)> {
        let mut explicit_defaults = Vec::<(&str, usize, usize)>::new();
        let mut versions = HashMap::<&str, Vec<(usize, usize)>>::new();

        for (i, func) in self.functions.iter().enumerate() {
            for (j, name) in func.names().iter().enumerate() {
                if let Some((prefix, _)) = name.split_once("@@") {
                    explicit_defaults.push((prefix, i, j));
                } else if let Some((prefix, _)) = name.split_once('@') {
                    versions.entry(prefix).or_default().push((i, j));
                }
            }
        }

        for (name, _, _) in &explicit_defaults {
            versions.remove(name);
        }
        versions.retain(|_, v| v.len() == 1);

        explicit_defaults.iter().map(|&(_, i, j)| (i, j)).chain(versions.into_values().map(|x| x[0])).collect()
    }

    fn finalize(mut self) -> Vec<ListingFunction> {
        self.flush();

        for (func, name) in self.find_default_versions() {
            self.functions[func].mark_name_default(name);
        }

        for func in &mut self.functions {
            func.finalize();
        }

        self.functions
    }
}

struct ListingParser<'a> {
    buf: &'a [u8],
    cursor: usize,
}

#[derive(Debug)]
enum ListingElem<'a> {
    Assembly(Option<&'a [u8]>, &'a [u8]),
    Continuation(&'a [u8]),
    Filename(&'a [u8]),
    Empty,
}

impl<'a> ListingParser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            cursor: 0,
        }
    }

    fn next_elem(&mut self) -> Option<ListingElem<'a>> {
        if self.cursor >= self.buf.len() {
            None
        } else {
            let line_start = self.cursor;
            let mut line_end = self.cursor;

            while line_end < self.buf.len() && self.buf[line_end] != b'\n' {
                line_end += 1;
            }

            self.cursor = line_end + 1;

            if line_start == line_end {
                return Some(ListingElem::Empty);
            }

            let line = &self.buf[line_start..line_end];
            let mut i = 0;

            /* Check if we have a page heading */
            if line[i] == 0xC {
                return Some(ListingElem::Empty);
            }

            /* Check if we have a EWE_SOURCE */
            if line.starts_with(EWE_SOURCE.as_bytes()) {
                return Some(ListingElem::Filename(&line[EWE_SOURCE.len() + 1..]));
            }

            /* Skip linenumber */
            while line[i] == b' ' {
                i += 1;
            }

            if !line[i].is_ascii_digit() {
                panic!("Expected linenumber");
            }

            while i < line.len() && line[i].is_ascii_digit() {
                i += 1;
            }

            if i >= line.len() {
                return Some(ListingElem::Empty);
            } else if line[i] != b' ' {
                panic!("Expected whitespace after linenumber");
            }
            i += 1;

            /* Check if we have a section offset (= beginning of new directive) */
            if is_hexchar(line[i]) {
                /* Skip the section offset */
                while is_hexchar(line[i]) {
                    i += 1;
                }

                if line[i] != b' ' {
                    panic!("Expected whitespace after section offset");
                }
                i += 1;

                let bytes_start = i;
                let mut bytes_end = bytes_start;

                while is_hexchar(line[bytes_end]) {
                    bytes_end += 1;
                }

                /* Skip whitespaces after bytes */
                i = bytes_end;

                while is_whitespace(line[i]) {
                    i += 1;
                }

                /* Check if we have a macro expansion */
                if i + 1 < line.len() && line[i] == b'>' && line[i + 1] == b' ' {
                    i += 2;

                    /* Skip whitespaces after macro expansion indicator */
                    while i < line.len() && is_whitespace(line[i]) {
                        i += 1;
                    }
                }

                /* Trim trailing whitespaces */
                let mut line_end = line.len() - 1;

                while line_end > i && is_whitespace(line[line_end]) {
                    line_end -= 1;
                }

                return Some(ListingElem::Assembly(Some(&line[bytes_start..bytes_end]), &line[i..line_end + 1]));
            }

            /* skip whitespaces for section offset */
            for _ in 0..4 + 1 {
                if line[i] != b' ' {
                    panic!("Expected whitespaces after line number");
                }
                i += 1;
            }

            /* Check if we have bytes (= continuation of previous directive) */
            if is_hexchar(line[i]) {
                let bytes_start = i;
                let mut bytes_end = bytes_start;

                while bytes_end < line.len() && is_hexchar(line[bytes_end]) {
                    bytes_end += 1;
                }

                /* Now only whitespaces may follow */
                i = bytes_end;

                while i < line.len() {
                    if is_whitespace(line[i]) {
                        i += 1;
                    } else {
                        panic!("Got unexpected data after assembly continuation");
                    }
                }

                return Some(ListingElem::Continuation(&line[bytes_start..bytes_end]));
            }

            /* Skip whitespaces until we hit directive */
            while i < line.len() && is_whitespace(line[i]) {
                i += 1;
            }

            /* Skip macro expansion indicator */
            if i + 1 < line.len() && line[i] == b'>' && line[i + 1] == b' ' {
                i += 2;

                while i < line.len() && is_whitespace(line[i]) {
                    i += 1;
                }
            }

            if i >= line.len() {
                return Some(ListingElem::Empty);
            }

            /* Trim trailing whitespaces */
            let mut line_end = line.len() - 1;

            while line_end > i && is_whitespace(line[line_end]) {
                line_end -= 1;
            }

            Some(ListingElem::Assembly(None, &line[i..line_end + 1]))
        }
    }
}

#[derive(Debug)]
pub struct Listing {
    functions: Vec<ListingFunction>,
}

impl Listing {
    pub fn from_file<P: AsRef<Path>>(filename: P) -> Self {
        let input = std::fs::read(filename.as_ref()).unwrap();
        let mut parser = ListingParser::new(&input);
        let mut builder = FunctionBuilder::new();
        let mut current_section = true;
        let mut previous_section = None;
        let mut section_stack = Vec::new();
        let mut known_sections = HashSet::<&str>::new();
        let mut inside_macro = false;

        while let Some(elem) = parser.next_elem() {
            /* Filter out listing elements that are in an executable section */
            match elem {
                ListingElem::Assembly(_, line) => {
                    if line[line.len() - 1] != b':' && line[0] == b'.' {
                        let directive = std::str::from_utf8(&line[1..]).unwrap();

                        if inside_macro {
                            if directive == "endm" || directive == "exitm" {
                                inside_macro = false;
                            }

                            continue;
                        }

                        if directive.starts_with("text") {
                            previous_section = Some(current_section);
                            current_section = true;
                        } else if directive.starts_with("data") || directive.starts_with("bss") {
                            previous_section = Some(current_section);
                            current_section = false;
                        } else if directive.starts_with("popsection") {
                            current_section = section_stack.pop().unwrap();
                        } else if directive.starts_with("previous") {
                            let tmp = previous_section.unwrap();
                            previous_section = Some(current_section);
                            current_section = tmp;
                        } else if directive.starts_with("pushsection") {
                            section_stack.push(current_section);
                            let (name, flags) = parse_section_directive(directive.as_bytes(), true);
                            current_section = name.starts_with(".text") || known_sections.contains(name);
                            if let Some(flags) = flags {
                                if flags.contains('x') {
                                    current_section = true;
                                    known_sections.insert(name);
                                }
                            }
                        } else if directive.starts_with("section") {
                            previous_section = Some(current_section);
                            let (name, flags) = parse_section_directive(directive.as_bytes(), false);
                            current_section = name.starts_with(".text") || known_sections.contains(name);
                            if let Some(flags) = flags {
                                if flags.contains('x') {
                                    current_section = true;
                                    known_sections.insert(name);
                                }
                            }
                        } else if directive.starts_with("macro") {
                            inside_macro = true;
                        }
                    }
                },
                ListingElem::Filename(name) => {
                    /* Always feed filename independent of section */
                    builder.feed_filename(name);
                    continue;
                },
                ListingElem::Continuation(_) => {},
                ListingElem::Empty => {
                    continue;
                },
            }

            if current_section && !inside_macro {
                builder.feed_elem(elem);
            }
        }

        Self {
            functions: builder.finalize(),
        }
    }

    pub fn match_symbol(&self, name: &str, size: Option<usize>, file: Option<&str>) -> Vec<&ListingFunction> {
        let mut result = Vec::new();
        let any_version = !name.contains('@');

        for func in &self.functions {
            if let Some(size) = size {
                if func.size() != size {
                    continue;
                }
            }
            if let Some(file) = file {
                if func.path().file_name().unwrap().to_str().unwrap() != file {
                    continue;
                }
            }

            let insert = if any_version { func.has_name_any_version(name) } else { func.has_name(name) };

            if insert {
                result.push(func);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_same_bb(funcs: &[&ListingFunction]) -> bool {
        let mut set = HashSet::new();

        for func in funcs {
            set.insert(func.boundaries());
        }

        set.len() == 1
    }

    fn check_listing(binary_path: &str) -> HashSet<String> {
        println!("Testing {}", binary_path);

        let mut ret = HashSet::new();
        let listing = Listing::from_file(format!("{}.{}", binary_path, EXTENSION));
        let buf = std::fs::read(binary_path).unwrap();
        let goblin::Object::Elf(elf) = goblin::Object::parse(&buf).unwrap() else { unreachable!() };
        let mut current_file = None;

        //println!("{:#?}", listing);

        for sym in elf.syms.iter() {
            if sym.st_type() == goblin::elf::sym::STT_FILE {
                let filename = elf.strtab.get_at(sym.st_name).unwrap();
                if filename.is_empty() {
                    current_file = None;
                } else {
                    current_file = Some(filename);
                }
            } else if sym.st_value != 0 && sym.is_function() {
                let symname = elf.strtab.get_at(sym.st_name).unwrap();
                let funcs = listing.match_symbol(symname, Some(sym.st_size as usize), current_file);

                if funcs.is_empty() {
                    ret.insert(symname.to_string());
                } else if funcs.len() > 1 {
                    assert!(check_same_bb(&funcs), "INVALID: {} ({:?})", symname, funcs);
                }
            }
        }

        for sym in elf.dynsyms.iter() {
            if !sym.is_import() && sym.is_function() {
                let symname = elf.dynstrtab.get_at(sym.st_name).unwrap();
                let funcs = listing.match_symbol(symname, Some(sym.st_size as usize), None);

                if funcs.is_empty() {
                    ret.insert(symname.to_string());
                } else if funcs.len() > 1 {
                    assert!(check_same_bb(&funcs), "INVALID: {} ({:?})", symname, funcs);
                }
            }
        }

        ret
    }

    #[test]
    fn check_functions() {
        let mut missing = HashSet::new();
        let paths = &[
            "test-data/glibc/build/libc.so",
            "test-data/glibc/build/math/libm.so",
            "test-data/glibc/build/dlfcn/libdl.so",
            "test-data/glibc/build/nptl_db/libthread_db.so",
            "test-data/glibc/build/login/libutil.so",
            "test-data/glibc/build/rt/librt.so",
            "test-data/glibc/build/malloc/libmemusage.so",
            "test-data/glibc/build/nptl/libpthread.so",
            "test-data/glibc/build/iconvdata/UTF-32.so",
            "test-data/glibc/build/nss/libnss_files.so",
            "test-data/glibc/build/nss/libnss_db.so",
            "test-data/glibc/build/nss/libnss_compat.so",
        ];

        for path in paths {
            missing = &missing | &check_listing(path);
        }

        println!("Missing: {:#?}", missing);
    }

    #[test]
    fn check_ant() {
        println!("Missing: {:#?}", check_listing("../ant/ld-linux-riscv64-lp64d.so.1"));
    }

    #[test]
    fn test_macro_expansions() {
        let mut parser = ListingParser::new(b" 22059 740c 13000000 	>  .align 4");

        while let Some(elem) = parser.next_elem() {
            println!("{:?}", elem);
        }

        let mut parser = ListingParser::new(b" 22059              	> ");

        while let Some(elem) = parser.next_elem() {
            println!("{:?}", elem);
        }
    }

    #[test]
    fn test_sysconf() {
        let listing = Listing::from_file("test-data/sysconf.ewe");
        println!("{:#?}", listing);
    }
}
