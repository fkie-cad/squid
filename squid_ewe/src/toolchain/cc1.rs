use std::{
    io::Write,
    process::{
        exit,
        Command,
    },
};

use crate::{
    asm::EWE_SOURCE,
    getopt::{
        GetoptParser,
        OptVal,
    },
};

#[derive(Debug)]
pub struct Cc1Wrapper {
    args: Vec<String>,
    inputs: Vec<String>,
    output: String,
}

impl Cc1Wrapper {
    pub fn from_cmdline(args: Vec<String>) -> Option<Self> {
        let parser = GetoptParser::new()
            .short('A', OptVal::Required, None)
            .short('C', OptVal::None, None)
            .long("CC", OptVal::None, None)
            .short('D', OptVal::Required, None)
            .short('F', OptVal::Required, None)
            .short('H', OptVal::None, None)
            .short('I', OptVal::Required, None)
            .short('J', OptVal::Required, None)
            .short('M', OptVal::Optional, None)
            .long("MF", OptVal::Required, None)
            .long("MQ", OptVal::Required, None)
            .long("MT", OptVal::Required, None)
            .long("MD", OptVal::Required, None)
            .long("MT", OptVal::Required, None)
            .short('P', OptVal::None, None)
            .short('U', OptVal::Required, None)
            .short('W', OptVal::Optional, None)
            .long("ansi", OptVal::None, None)
            .short('d', OptVal::Required, None)
            .short('f', OptVal::Required, None)
            .long("gen-decls", OptVal::None, None)
            .long("idirafter", OptVal::Required, None)
            .long("imacros", OptVal::Required, None)
            .long("imultilib", OptVal::Required, None)
            .long("include", OptVal::Required, None)
            .long("iprefix", OptVal::Required, None)
            .long("iquote", OptVal::Required, None)
            .long("isysroot", OptVal::Required, None)
            .long("isystem", OptVal::Required, None)
            .long("iwithprefix", OptVal::Required, None)
            .long("iwithprefixbefore", OptVal::Required, None)
            .long("nostdinc", OptVal::None, None)
            .short('o', OptVal::Required, None)
            .long("remap", OptVal::None, None)
            .long("std", OptVal::Required, None)
            .long("param", OptVal::Required, None)
            .short('O', OptVal::Required, None)
            .short('m', OptVal::Required, None)
            .long("help", OptVal::Optional, None)
            .long("target-help", OptVal::None, None)
            .long("aux-info", OptVal::Required, None)
            .long("dumpbase", OptVal::Required, None)
            .long("dumpbase-ext", OptVal::Required, None)
            .long("dumpdir", OptVal::Required, None)
            .short('g', OptVal::Optional, None)
            .long("imultiarch", OptVal::Required, None)
            .long("iplugindir", OptVal::Required, None)
            .long("quiet", OptVal::None, None)
            .short('E', OptVal::None, None)
            .long("lang-asm", OptVal::None, None)
            .long("version", OptVal::None, None)
            .long("pedantic-errors", OptVal::None, None)
            .short('p', OptVal::None, None)
            .short('v', OptVal::None, None)
            .short('w', OptVal::None, None)
            .long("print-objc-runtime-info", OptVal::None, None)
            .long("nostdlib", OptVal::None, None)
            .long("nostdinc++", OptVal::None, None)
            .long("undef", OptVal::None, None);

        let cmdline = parser.parse_long_only(&args).unwrap();
        let output = if let Some(output) = cmdline.arg_value('o') {
            output.to_string()
        } else {
            return None;
        };

        let mut inputs = Vec::new();

        for input in cmdline.positionals() {
            if *input != "-" {
                inputs.push(input.to_string());
            }
        }

        if inputs.is_empty() {
            None
        } else {
            Some(Self {
                args,
                inputs,
                output,
            })
        }
    }

    pub fn compile(&self) {
        let status = Command::new(&self.args[0]).args(&self.args[1..]).envs(std::env::vars()).status().unwrap();

        if let Some(code) = status.code() {
            if code != 0 {
                exit(code);
            }
        } else {
            exit(-1);
        }
    }

    pub fn postprocess(&self) {
        let content = std::fs::read(&self.output).unwrap();
        let mut output = std::fs::OpenOptions::new().write(true).truncate(true).open(&self.output).unwrap();

        for input in &self.inputs {
            let input = std::path::Path::new(input);
            let input = input.canonicalize().unwrap();
            writeln!(&mut output, ".title \"{EWE_SOURCE}={}\"", input.display()).unwrap();
        }

        output.write_all(&content).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmdline() {
        let wrapper = Cc1Wrapper::from_cmdline(vec![
            "cc1".to_string(),
            "-DX=Y".to_string(),
            "-I/asdf/".to_string(),
            "-MD".to_string(),
            "-MF".to_string(),
            "asdf".to_string(),
            "-W".to_string(),
            "-Wabi=ilp64".to_string(),
            "-fbuiltin".to_string(),
            "-fsanitize=address".to_string(),
            "-o".to_string(),
            "output".to_string(),
            "-std=gnu9x".to_string(),
            "--param=align-loop-iterations=4".to_string(),
            "-O3".to_string(),
            "-mabi=ilp64".to_string(),
            "-mplt".to_string(),
            "-g".to_string(),
            "source1.c".to_string(),
        ])
        .unwrap();
        println!("{:?}", wrapper);
    }

    #[test]
    fn test_glibc() {
        let wrapper = Cc1Wrapper::from_cmdline(vec![
            "riscv/libexec/gcc/riscv64-unknown-linux-gnu/12.2.0/cc1".to_string(),
            "-quiet".to_string(),
            "-I".to_string(),
            "../include".to_string(),
            "-MD".to_string(),
            "/io/test-data/glibc/build/libio/clearerr.d".to_string(),
            "-MF".to_string(),
            "/io/test-data/glibc/build/libio/clearerr.os.dt".to_string(),
            "-MP".to_string(),
            "-MT".to_string(),
            "/io/test-data/glibc/build/libio/clearerr.os".to_string(),
            "-D".to_string(),
            "MODULE_NAME=libc".to_string(),
            "-include".to_string(),
            "/io/test-data/glibc/build/libc-modules.h".to_string(),
            "clearerr.c".to_string(),
            "-quiet".to_string(),
            "-dumpdir".to_string(),
            "/io/test-data/glibc/build/libio/".to_string(),
            "-dumpbase".to_string(),
            "clearerr.c".to_string(),
            "-dumpbase-ext".to_string(),
            ".c".to_string(),
            "-mtune=rocket".to_string(),
            "-march=rv64imafd".to_string(),
            "-mabi=lp64d".to_string(),
            "-misa-spec=2.2".to_string(),
            "-march=rv64imafd".to_string(),
            "-g".to_string(),
            "-O2".to_string(),
            "-Wall".to_string(),
            "-Wwrite-strings".to_string(),
            "-Wundef".to_string(),
            "-Wstrict-prototypes".to_string(),
            "-Wold-style-definition".to_string(),
            "-std=gnu11".to_string(),
            "-fgnu89-inline".to_string(),
            "-fmerge-all-constants".to_string(),
            "-frounding-math".to_string(),
            "-fstack-protector-all".to_string(),
            "-fmath-errno".to_string(),
            "-fPIC".to_string(),
            "-ftls-model=initial-exec".to_string(),
            "-o".to_string(),
            "/tmp/ccwcOLk1.s".to_string(),
        ])
        .unwrap();
        println!("{:?}", wrapper);
    }
}
