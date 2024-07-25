use std::{
    io::Write,
    process::{
        exit,
        Command,
    },
};

use crate::{
    asm::separate_statements,
    getopt::{
        GetoptParser,
        OptVal,
    },
    listing::EXTENSION,
};

const OPTION_BLACKLIST: [&str; 1] = ["-mrelax"];

#[derive(Debug)]
pub struct AsWrapper {
    args: Vec<String>,
    inputs: Vec<String>,
    output: String,
}

impl AsWrapper {
    pub fn from_cmdline(args: Vec<String>) -> Option<Self> {
        let parser = GetoptParser::new()
            .optstring("o:JKLMRWZa::Dg::I:vwXt:")
            .optstring("O::g::G:")
            .long("alternate", OptVal::None, None)
            .long("compress-debug-sections", OptVal::Optional, None)
            .long("nocompress-debug-sections", OptVal::None, None)
            .long("debug-prefix-map", OptVal::Required, None)
            .long("defsym", OptVal::Required, None)
            .long("dump-config", OptVal::None, None)
            .long("emulation", OptVal::Required, None)
            .long("execstack", OptVal::None, None)
            .long("noexecstack", OptVal::None, None)
            .long("size-check", OptVal::Required, None)
            .long("elf-stt-common", OptVal::Required, None)
            .long("sectname-subst", OptVal::None, None)
            .long("generate-missing-build-notes", OptVal::Required, None)
            .long("fatal-warnings", OptVal::None, None)
            .long("gdwarf-cie-version", OptVal::Required, None)
            .long("gen-debug", OptVal::None, None)
            .long("gstabs", OptVal::None, None)
            .long("gstabs+", OptVal::None, None)
            .long("gdwarf-2", OptVal::None, None)
            .long("gdwarf-3", OptVal::None, None)
            .long("gdwarf-4", OptVal::None, None)
            .long("gdwarf-5", OptVal::None, None)
            .long("gdwarf-sections", OptVal::None, None)
            .long("hash-size", OptVal::Required, None)
            .long("help", OptVal::None, None)
            .long("itbl", OptVal::Required, None)
            .long("keep-locals", OptVal::None, None)
            .long("listing-lhs-width", OptVal::Required, None)
            .long("listing-lhs-width2", OptVal::Required, None)
            .long("listing-rhs-width", OptVal::Required, None)
            .long("listing-cont-lines", OptVal::Required, None)
            .long("MD", OptVal::Required, None)
            .long("mri", OptVal::None, None)
            .long("nocpp", OptVal::None, None)
            .long("no-pad-sections", OptVal::None, None)
            .long("no-warn", OptVal::None, None)
            .long("reduce-memory-overheads", OptVal::None, None)
            .long("statistics", OptVal::None, None)
            .long("strip-local-absolute", OptVal::None, None)
            .long("version", OptVal::None, None)
            .long("verbose", OptVal::None, None)
            .long("target-help", OptVal::None, None)
            .long("traditional-format", OptVal::None, None)
            .long("warn", OptVal::None, None)
            .long("multibyte-handling", OptVal::Required, None)
            .long("march", OptVal::Required, None)
            .short('f', OptVal::Required, None)
            .long("mabi", OptVal::Required, None)
            .long("misa-spec", OptVal::Required, None)
            .long("mpriv-spec", OptVal::Required, None)
            .short('m', OptVal::Required, None);

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

        Some(Self {
            args,
            inputs,
            output,
        })
    }

    pub fn preprocess(&self) {
        for filename in &self.inputs {
            let input = std::fs::read(filename).unwrap();
            let output = separate_statements(&input, filename);
            let mut file = std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(filename).unwrap();
            file.write_all(&output).unwrap();
        }
    }

    pub fn compile(&self) {
        let listing = format!("{}.{}", self.output, EXTENSION);
        let status = Command::new(&self.args[0])
            .arg(format!("-almd={listing}"))
            .args(self.args[1..].iter().filter(|x| !OPTION_BLACKLIST.contains(&x.as_str())))
            .arg("-mno-relax")
            .envs(std::env::vars())
            .status()
            .unwrap();

        if let Some(code) = status.code() {
            if code != 0 {
                exit(code);
            }
        } else {
            exit(-1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assembly_preprocessing() {
        let output = separate_statements(
            b".file \":;\\\"\\\\\"# single-line comment\n/* multi-line\ncomment */.L0:.directive;inst;\n",
            "<test>",
        );
        println!("{}", std::str::from_utf8(&output).unwrap());
    }

    #[test]
    fn test_as_wrapper1() {
        let wrapper = AsWrapper::from_cmdline(vec!["as".to_string(), "--help".to_string()]);
        assert!(wrapper.is_none());
    }

    #[test]
    fn test_as_wrapper2() {
        let wrapper = AsWrapper::from_cmdline(vec![
            "as".to_string(),
            "-fpic".to_string(),
            "--traditional-format".to_string(),
            "-march=rv64imafd".to_string(),
            "-mabi=lp64d".to_string(),
            "-misa-spec=2.2".to_string(),
            "-o".to_string(),
            "/tmp/cc5hz51Q.o".to_string(),
            "/tmp/ccNyPyiT.s".to_string(),
            "-".to_string(),
        ])
        .unwrap();
        assert_eq!(wrapper.inputs, &["/tmp/ccNyPyiT.s"]);
        assert_eq!(wrapper.output, "/tmp/cc5hz51Q.o");
    }

    #[test]
    fn test_glibc() {
        let wrapper = AsWrapper::from_cmdline(vec![
            "as".to_string(),
            "-I".to_string(),
            "../include".to_string(),
            "--gdwarf-5".to_string(),
            "--traditional-format".to_string(),
            "-fpic".to_string(),
            "-march=rv64imafd".to_string(),
            "-march=rv64imafd".to_string(),
            "-mabi=lp64d".to_string(),
            "-misa-spec=2.2".to_string(),
            "-o".to_string(),
            "/io/test-data/glibc/build/libio/clearerr.os".to_string(),
            "/tmp/ccJfUCIc.s".to_string(),
        ])
        .unwrap();
        println!("{:?}", wrapper);
    }
}
