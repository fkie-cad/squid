use std::{
    env,
    process::{
        exit,
        Command,
    },
};

use squid_ewe::{
    container::*,
    env::*,
};

fn build_cmd() -> Command {
    let nostdlib = env_flag(EWE_NOSTDLIB);
    let wrapper_path = env_value(EWE_WRAPPER, EWE_WRAPPER_PATH);

    let mut cmd = Command::new(wrapper_path);
    cmd.arg(env_value(RISCV_LD, RISCV_LD_PATH));

    if nostdlib {
        cmd.arg("-nostdlib");
        cmd.arg(env_value(RISCV_CRT1, RISCV_CRT1_PATH));
    }

    cmd.args(env::args().skip(1));

    if nostdlib {
        cmd.arg("-L");
        cmd.arg(RISCV_LIB_PATH);
        cmd.arg("-lc");
    }

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
