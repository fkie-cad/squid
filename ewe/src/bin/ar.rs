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

fn build_cmd() -> Command {
    let wrapper_path = env_value(EWE_WRAPPER, EWE_WRAPPER_PATH);
    let mut cmd = Command::new(wrapper_path);
    cmd.arg(env_value(RISCV_AR, RISCV_AR_PATH));
    cmd.args(env::args().skip(1));
    cmd
}

fn main() -> ! {
    let status = build_cmd().envs(env::vars()).status().unwrap();

    if let Some(code) = status.code() {
        exit(code);
    } else {
        exit(-1);
    }
}
