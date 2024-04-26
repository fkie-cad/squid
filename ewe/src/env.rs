pub const EWE_WRAPPER: &str = "EWE_WRAPPER";
pub const EWE_AS: &str = "EWE_AS";
pub const EWE_LD: &str = "EWE_LD";
pub const EWE_AR: &str = "EWE_AR";
pub const EWE_NOSTDLIB: &str = "EWE_NOSTDLIB";
pub const RISCV_GCC: &str = "RISCV_GCC";
pub const RISCV_GPP: &str = "RISCV_G++";
pub const RISCV_CRT1: &str = "RISCV_CRT1";
pub const RISCV_AR: &str = "RISCV_AR";
pub const RISCV_AS: &str = "RISCV_AS";
pub const RISCV_LD: &str = "RISCV_LD";

pub fn env_value(key: &str, default: &str) -> String {
    if let Ok(value) = std::env::var(key) {
        value
    } else {
        default.to_string()
    }
}

pub fn env_flag(key: &str) -> bool {
    if let Ok(value) = std::env::var(key) {
        matches!(value.to_ascii_lowercase().as_str(), "1" | "yes" | "on" | "true")
    } else {
        false
    }
}
