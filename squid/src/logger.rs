#[cfg(feature = "tui")]
use core::time::Duration;
use std::{
    borrow::Cow,
    fmt::Display,
};

use colored::Colorize;
use indicatif::{
    ProgressBar,
    ProgressStyle,
};

pub struct Logger {
    bar: ProgressBar,
    running: bool,
    prefix: Option<String>,
}

#[cfg(feature = "tui")]
const ANIMATION: &[&str; 9] = &[".  ", ".. ", "...", " ..", "  .", " ..", "...", "..", ""];

#[cfg(not(feature = "tui"))]
const ANIMATION: &[&str; 2] = &["...", ""];

impl Logger {
    pub(crate) fn spinner() -> Self {
        let bar = ProgressBar::new_spinner();
        bar.set_style(ProgressStyle::with_template("{prefix:.magenta/red} {msg} {spinner}").unwrap().tick_strings(ANIMATION));
        bar.set_prefix("[🦑]");

        Self {
            bar,
            running: false,
            prefix: None,
        }
    }

    pub(crate) fn set_prefix<S: Into<String>>(&mut self, prefix: S) {
        self.prefix = Some(prefix.into());
    }

    pub(crate) fn clear_prefix(&mut self) {
        self.prefix = None;
    }

    pub(crate) fn set_title(&mut self, title: impl Into<Cow<'static, str>>) {
        #[cfg(feature = "tui")]
        if !self.running {
            self.bar.enable_steady_tick(Duration::from_millis(100));
            self.running = true;
        }
        self.bar.set_message(title.into());
    }

    fn stop(&mut self) {
        if self.running {
            self.running = false;
            self.bar.finish_and_clear();
        }
    }

    fn emit<L: Display, S: AsRef<str>>(&self, level: L, msg: S) {
        if let Some(prefix) = &self.prefix {
            self.bar.println(format!("{} {}{}{} {}", level, "(".bold(), prefix.bold(), ")".bold(), msg.as_ref()))
        } else {
            self.bar.println(format!("{} {}", level, msg.as_ref()));
        }
    }

    pub fn info<S: AsRef<str>>(&self, msg: S) {
        self.emit("[🦑::INFO]".blue().bold(), msg);
    }

    pub fn warning<S: AsRef<str>>(&self, msg: S) {
        self.emit("[🦑::WARN]".yellow().bold(), msg);
    }

    pub fn debug<S: AsRef<str>>(&self, _msg: S) {
        #[cfg(debug_assertions)]
        {
            self.emit("[🦑::DEBUG]".black().on_white(), _msg);
        }
    }

    pub fn error<S: AsRef<str>>(&self, msg: S) {
        self.emit("[🦑::ERROR]".red().bold(), msg);
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_style() {
        let mut logger = Logger::spinner();
        logger.set_title("TITLE HERE");
        logger.info("info");
        logger.warning("warning");
        logger.debug("debug");
        logger.error("error");

        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
