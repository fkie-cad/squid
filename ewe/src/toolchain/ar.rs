use std::{
    fs::OpenOptions,
    io::Write,
    process::{
        exit,
        Command,
    },
};

use crate::{
    getopt::{
        ArgList,
        GetoptParser,
        OptVal,
    },
    listing::EXTENSION,
};

fn command_as_opt(cmdline: &ArgList) -> bool {
    cmdline.arg_present('d')
        || cmdline.arg_present('m')
        || cmdline.arg_present('p')
        || cmdline.arg_present('q')
        || cmdline.arg_present('r')
        || cmdline.arg_present('s')
        || cmdline.arg_present('t')
        || cmdline.arg_present('x')
}

#[derive(Debug)]
pub struct ArWrapper {
    args: Vec<String>,
    inputs: Vec<String>,
    output: String,
}

impl ArWrapper {
    pub fn from_cmdline(args: Vec<String>) -> Option<Self> {
        let parser = GetoptParser::new()
            .optstring("dmpqrstxabcDfiMNoOPsSTuvV")
            .long("plugin", OptVal::Required, None)
            .long("target", OptVal::Required, None)
            .long("output", OptVal::Required, None)
            .long("record-libdeps", OptVal::Required, None)
            .long("thin", OptVal::None, None)
            .short('M', OptVal::Required, None);
        let cmdline = parser.parse_long(&args).unwrap();
        let mut i;

        if cmdline.arg_present('M') {
            return None;
        }

        let is_create = if command_as_opt(&cmdline) {
            i = 0;
            cmdline.arg_present('q') || cmdline.arg_present('r')
        } else {
            i = 1;
            let command = cmdline.positionals()[0];
            command.contains('q') || command.contains('r')
        };

        if !is_create {
            return None;
        }

        let mut inputs = Vec::new();
        let output = cmdline.positionals()[i].to_string();

        i += 1;

        while i < cmdline.positionals().len() {
            inputs.push(cmdline.positionals()[i].to_string());
            i += 1;
        }

        Some(Self {
            args,
            inputs,
            output,
        })
    }

    pub fn archive(&self) {
        /* Run ar */
        let status = Command::new(&self.args[0]).args(&self.args[1..]).envs(std::env::vars()).status().unwrap();

        if let Some(code) = status.code() {
            if code != 0 {
                exit(code);
            }
        } else {
            exit(-1);
        }

        /* Merge metadata files */
        let mut output = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .append(true)
            .open(format!("{}.{}", self.output, EXTENSION))
            .unwrap();

        for input in &self.inputs {
            let input = OpenOptions::new().read(true).open(format!("{input}.{EXTENSION}"));

            if let Ok(mut input) = input {
                output.write_all(&[0xC]).unwrap();
                std::io::copy(&mut input, &mut output).unwrap();
                output.write_all(&[0xA]).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glibc() {
        let wrapper = ArWrapper::from_cmdline(vec![
            "/ewe/ar".to_string(),
            "cr".to_string(),
            "librpc_compat_pic.a".to_string(),
            "compat-auth_des.os".to_string(),
            "compat-auth_unix.os".to_string(),
            "compat-clnt_gen.os".to_string(),
        ]);
        println!("{:?}", wrapper);
    }
}
