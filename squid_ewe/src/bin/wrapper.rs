use std::{
    env,
    path::Path,
    process::{
        exit,
        Command,
    },
};

use squid_ewe::{
    container::RISCV_PREFIX,
    toolchain::{
        ArWrapper,
        AsWrapper,
        Cc1Wrapper,
        LdWrapper,
    },
};

fn forward() -> ! {
    let mut args = env::args().skip(1);
    let status = Command::new(args.next().unwrap()).args(args).envs(env::vars()).status().unwrap();

    if let Some(code) = status.code() {
        exit(code);
    } else {
        exit(-1);
    }
}

fn extract_program(args: &[String]) -> Option<&str> {
    let arg = args.first()?;
    let path = Path::new(arg);
    path.file_name().and_then(|x| x.to_str()).map(|x| {
        if x.starts_with(RISCV_PREFIX) {
            &x[RISCV_PREFIX.len() + 1..]
        } else {
            x
        }
    })
}

fn usage(prog: &str) {
    println!("USAGE: {prog} <wrapped program> <wrapped args..>");
    println!();
    println!("Use this program with: gcc -wrapper {prog}");
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<String>>();

    match extract_program(&args) {
        Some("cc1") => {
            if let Some(wrapper) = Cc1Wrapper::from_cmdline(args) {
                #[cfg(debug_assertions)]
                eprintln!("[EWE]  -> {wrapper:?}");

                wrapper.compile();
                wrapper.postprocess();
                exit(0);
            }
        },
        Some("as") => {
            if let Some(wrapper) = AsWrapper::from_cmdline(args) {
                #[cfg(debug_assertions)]
                eprintln!("[EWE]  -> {wrapper:?}");

                wrapper.preprocess();
                wrapper.compile();
                exit(0);
            }
        },
        Some("ld") | Some("collect2") => {
            if let Some(wrapper) = LdWrapper::from_cmdline(args) {
                #[cfg(debug_assertions)]
                eprintln!("[EWE]  -> {wrapper:?}");

                wrapper.link();
                exit(0);
            }
        },
        Some("ar") => {
            if let Some(wrapper) = ArWrapper::from_cmdline(args) {
                #[cfg(debug_assertions)]
                eprintln!("[EWE]  -> {wrapper:?}");

                wrapper.archive();
                exit(0);
            }
        },
        Some(_prog) => {
            // Ignore other subprograms
            #[cfg(debug_assertions)]
            eprintln!("[EWE] Ignoring {_prog}");
        },
        None => {
            usage(&args[0]);
            exit(1);
        },
    }

    forward()
}
