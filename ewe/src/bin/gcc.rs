use std::{
    env,
    process::{
        exit,
        Command,
    },
};

use ewe::{
    container::*,
    env::*,
};

fn build_cmd(args: &[String]) -> Command {
    #[cfg(debug_assertions)]
    eprintln!("[EWE] {args:?}");

    let mut is_cpp = false;
    let nostdlib = env_flag(EWE_NOSTDLIB);

    let prog_path = if args[0].ends_with("gcc") {
        env_value(RISCV_GCC, RISCV_GCC_PATH)
    } else if args[0].ends_with("g++") {
        is_cpp = true;
        env_value(RISCV_GPP, RISCV_GPP_PATH)
    } else {
        panic!("Invalid program name {}", args[0])
    };

    let mut cmd = Command::new(prog_path);

    cmd.arg("-wrapper");
    cmd.arg(env_value(EWE_WRAPPER, EWE_WRAPPER_PATH));

    if nostdlib {
        if is_cpp {
            todo!("C++ not supported yet");
        } else {
            cmd.arg("-nostdlib");
        }

        cmd.arg(env_value(RISCV_CRT1, RISCV_CRT1_PATH));
    }

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-pipe" => {
                continue;
            },
            _ => {
                cmd.arg(arg);
            },
        }
    }

    if nostdlib {
        if is_cpp {
            todo!();
        } else {
            cmd.arg("-lc");
        }
    }

    cmd
}

fn has_print_prog_name(args: &[String]) -> Option<usize> {
    for (i, arg) in args.iter().enumerate().skip(1) {
        if arg.starts_with("-print-prog-name=") {
            return Some(i);
        }
    }

    None
}

fn check_misc_action(args: &mut Vec<String>) {
    if let Some(i) = has_print_prog_name(args) {
        let (_, prog) = args[i].split_once('=').unwrap();

        let hooked = match prog {
            "ar" => {
                println!("{}", env_value(EWE_AR, EWE_AR_PATH));
                true
            },
            "as" => {
                println!("{}", env_value(EWE_AS, EWE_AS_PATH));
                true
            },
            "ld" => {
                println!("{}", env_value(EWE_LD, EWE_LD_PATH));
                true
            },
            _ => false,
        };

        if hooked {
            args.remove(i);

            if args.len() <= 1 {
                exit(0);
            }
        }
    }
}

fn main() -> ! {
    let mut args = env::args().collect::<Vec<String>>();

    check_misc_action(&mut args);

    let status = build_cmd(&args).envs(env::vars()).status().unwrap();

    if let Some(code) = status.code() {
        exit(code);
    } else {
        exit(-1);
    }
}
