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
        GetoptParser,
        OptVal,
    },
    listing::EXTENSION,
};

const OPTION_BLACKLIST: [&str; 1] = ["--relax"];

#[derive(Debug)]
pub struct LdWrapper {
    args: Vec<String>,
    inputs: Vec<String>,
    output: String,
}

impl LdWrapper {
    pub fn from_cmdline(args: Vec<String>) -> Option<Self> {
        let parser = GetoptParser::new()
            .short('a', OptVal::Required, None)
            .short('A', OptVal::Required, None)
            .long("architecture", OptVal::Required, None)
            .short('b', OptVal::Required, None)
            .long("format", OptVal::Required, None)
            .short('c', OptVal::Required, None)
            .long("mri-script", OptVal::Required, None)
            .short('d', OptVal::Optional, None)
            .long("dependency-file", OptVal::Required, None)
            .long("force-group-allocation", OptVal::None, None)
            .short('e', OptVal::Required, None)
            .long("entry", OptVal::Required, None)
            .short('E', OptVal::None, None)
            .long("export-dynamic", OptVal::None, None)
            .long("no-export-dynamic", OptVal::None, None)
            .long("enable-non-contiguous-regions", OptVal::None, None)
            .long("enable-non-contiguous-regions-warnings", OptVal::None, None)
            .long("EB", OptVal::None, None)
            .long("EL", OptVal::None, None)
            .short('f', OptVal::Required, None)
            .long("auxiliary", OptVal::Required, None)
            .short('F', OptVal::Required, None)
            .long("filter", OptVal::Required, None)
            .short('g', OptVal::None, None)
            .short('G', OptVal::Required, None)
            .long("gpsize", OptVal::Required, None)
            .short('h', OptVal::Required, None)
            .long("soname", OptVal::Required, None)
            .short('I', OptVal::Required, None)
            .long("dynamic-linker", OptVal::Required, None)
            .long("no-dynamic-linker", OptVal::None, None)
            .short('l', OptVal::Required, None)
            .long("library", OptVal::Required, None)
            .short('L', OptVal::Required, None)
            .long("library-path", OptVal::Required, None)
            .long("sysroot", OptVal::Required, None)
            .short('m', OptVal::Required, None)
            .short('M', OptVal::None, None)
            .long("print-map", OptVal::None, None)
            .short('n', OptVal::None, None)
            .long("nmagic", OptVal::None, None)
            .short('N', OptVal::None, None)
            .long("omagic", OptVal::None, None)
            .long("no-omagic", OptVal::None, None)
            .short('o', OptVal::Required, Some("a.out"))
            .long("output", OptVal::Required, None)
            .short('O', OptVal::Optional, None)
            .long("out-implib", OptVal::Required, None)
            .long("plugin", OptVal::Required, None)
            .long("plugin-opt", OptVal::Required, None)
            .long("flto", OptVal::None, None)
            .long("flto-partition", OptVal::Required, None)
            .long("fuse-ld", OptVal::Required, None)
            .long("map-whole-files", OptVal::None, None)
            .long("no-map-whole-files", OptVal::None, None)
            .long("Qy", OptVal::None, None)
            .short('q', OptVal::None, None)
            .long("emit-relocs", OptVal::None, None)
            .short('r', OptVal::None, None)
            .short('i', OptVal::None, None)
            .long("relocatable", OptVal::None, None)
            .short('R', OptVal::Required, None)
            .long("just-symbols", OptVal::Required, None)
            .short('s', OptVal::None, None)
            .long("strip-all", OptVal::None, None)
            .short('S', OptVal::None, None)
            .long("strip-debug", OptVal::None, None)
            .long("strip-discarded", OptVal::None, None)
            .long("no-strip-discarded", OptVal::None, None)
            .short('t', OptVal::None, None)
            .long("trace", OptVal::None, None)
            .short('T', OptVal::Required, None)
            .long("script", OptVal::Required, None)
            .long("default-script", OptVal::Required, None)
            .long("dT", OptVal::None, None)
            .short('u', OptVal::Required, None)
            .long("undefined", OptVal::Required, None)
            .long("require-defined", OptVal::Required, None)
            .long("unique", OptVal::Optional, None)
            .long("Ur", OptVal::None, None)
            .short('v', OptVal::None, None)
            .long("version", OptVal::None, None)
            .short('V', OptVal::None, None)
            .short('x', OptVal::None, None)
            .long("discard-all", OptVal::None, None)
            .short('X', OptVal::None, None)
            .long("discard-locals", OptVal::None, None)
            .long("discard-none", OptVal::None, None)
            .short('y', OptVal::Required, None)
            .long("trace-symbol", OptVal::Required, None)
            .short('Y', OptVal::Required, None)
            .short('(', OptVal::None, None)
            .long("start-group", OptVal::None, None)
            .short(')', OptVal::None, None)
            .long("end-group", OptVal::None, None)
            .long("accept-unknown-input-arch", OptVal::None, None)
            .long("no-accept-unknown-input-arch", OptVal::None, None)
            .long("as-needed", OptVal::None, None)
            .long("no-as-needed", OptVal::None, None)
            .short('B', OptVal::Required, None)
            .long("dy", OptVal::None, None)
            .long("call_shared", OptVal::None, None)
            .long("dn", OptVal::None, None)
            .long("non_shared", OptVal::None, None)
            .long("static", OptVal::None, None)
            .long("check-sections", OptVal::None, None)
            .long("no-check-sections", OptVal::None, None)
            .long("copy-dt-needed-entries", OptVal::None, None)
            .long("no-copy-dt-needed-entries", OptVal::None, None)
            .long("cref", OptVal::None, None)
            .long("defsym", OptVal::Required, None)
            .long("demangle", OptVal::Optional, None)
            .long("disable-multiple-abs-defs", OptVal::None, None)
            .long("embedded-relocs", OptVal::None, None)
            .long("fatal-warnings", OptVal::None, None)
            .long("no-fatal-warnings", OptVal::None, None)
            .long("fini", OptVal::Required, None)
            .long("force-exe-suffix", OptVal::None, None)
            .long("gc-sections", OptVal::None, None)
            .long("no-gc-sections", OptVal::None, None)
            .long("print-gc-sections", OptVal::None, None)
            .long("no-print-gc-sections", OptVal::None, None)
            .long("gc-keep-exported", OptVal::None, None)
            .long("hash-size", OptVal::Required, None)
            .long("help", OptVal::None, None)
            .long("init", OptVal::Required, None)
            .long("Map", OptVal::Required, None)
            .long("no-define-common", OptVal::None, None)
            .long("no-demangle", OptVal::None, None)
            .long("no-keep-memory", OptVal::None, None)
            .long("no-undefined", OptVal::None, None)
            .long("allow-shlib-undefined", OptVal::None, None)
            .long("no-allow-shlib-undefined", OptVal::None, None)
            .long("allow-multiple-definition", OptVal::None, None)
            .long("error-handling-script", OptVal::Required, None)
            .long("no-undefined-version", OptVal::None, None)
            .long("default-symver", OptVal::None, None)
            .long("default-imported-symver", OptVal::None, None)
            .long("no-warn-mismatch", OptVal::None, None)
            .long("no-warn-search-mismatch", OptVal::None, None)
            .long("no-whole-archive", OptVal::None, None)
            .long("noinhibit-exec", OptVal::None, None)
            .long("nostdlib", OptVal::None, None)
            .long("oformat", OptVal::Required, None)
            .long("print-output-format", OptVal::None, None)
            .long("print-sysroot", OptVal::None, None)
            .long("qmagic", OptVal::None, None)
            .long("reduce-memory-overheads", OptVal::None, None)
            .long("max-cache-size", OptVal::Required, None)
            .long("relax", OptVal::None, None)
            .long("no-relax", OptVal::None, None)
            .long("retain-symbols-file", OptVal::Required, None)
            .long("rpath", OptVal::Required, None)
            .long("rpath-link", OptVal::Required, None)
            .long("shared", OptVal::None, None)
            .long("pie", OptVal::None, None)
            .long("pic-executable", OptVal::None, None)
            .long("no-pie", OptVal::None, None)
            .long("sort-common", OptVal::Optional, None)
            .long("sort-section", OptVal::Required, None)
            .long("spare-dynamic-tags", OptVal::Required, None)
            .long("split-by-file", OptVal::Optional, None)
            .long("split-by-reloc", OptVal::Optional, None)
            .long("stats", OptVal::None, None)
            .long("target-help", OptVal::None, None)
            .long("task-link", OptVal::Required, None)
            .long("traditional-format", OptVal::None, None)
            .long("section-start", OptVal::Required, None)
            .long("Tbss", OptVal::Required, None)
            .long("Tdata", OptVal::Required, None)
            .long("Ttext", OptVal::Required, None)
            .long("Ttext-segment", OptVal::Required, None)
            .long("Trodata-segment", OptVal::Required, None)
            .long("Tldata-segment", OptVal::Required, None)
            .long("unresolved-symbols", OptVal::Required, None)
            .long("verbose", OptVal::Optional, None)
            .long("version-script", OptVal::Required, None)
            .long("version-exports-section", OptVal::Required, None)
            .long("dynamic-list-data", OptVal::None, None)
            .long("dynamic-list-cpp-new", OptVal::None, None)
            .long("dynamic-list-cpp-typeinfo", OptVal::None, None)
            .long("dynamic-list", OptVal::Required, None)
            .long("export-dynamic-symbol", OptVal::Required, None)
            .long("export-dynamic-symbol-list", OptVal::Required, None)
            .long("warn-common", OptVal::None, None)
            .long("warn-constructors", OptVal::None, None)
            .long("warn-execstack", OptVal::None, None)
            .long("no-warn-execstack", OptVal::None, None)
            .long("warn-rwx-segments", OptVal::None, None)
            .long("no-warn-rwx-segments", OptVal::None, None)
            .long("warn-multiple-gp", OptVal::None, None)
            .long("warn-once", OptVal::None, None)
            .long("warn-section-align", OptVal::None, None)
            .long("warn-textrel", OptVal::None, None)
            .long("warn-alternate-em", OptVal::None, None)
            .long("warn-unresolved-symbols", OptVal::None, None)
            .long("error-unresolved-symbols", OptVal::None, None)
            .long("whole-archive", OptVal::None, None)
            .long("wrap", OptVal::Required, None)
            .long("ignore-unresolved-symbol", OptVal::Required, None)
            .long("push-state", OptVal::None, None)
            .long("pop-state", OptVal::None, None)
            .long("print-memory-usage", OptVal::None, None)
            .long("orphan-handling", OptVal::Required, None)
            .long("print-map-discarded", OptVal::None, None)
            .long("no-print-map-discarded", OptVal::None, None)
            .long("ctf-variables", OptVal::None, None)
            .long("no-ctf-variables", OptVal::None, None)
            .long("ctf-share-types", OptVal::Required, None)
            .long("build-id", OptVal::Optional, None)
            .long("package-metadata", OptVal::Optional, None)
            .long("compress-debug-sections", OptVal::Required, None)
            .short('z', OptVal::Required, None)
            .long("audit", OptVal::Required, None)
            .long("disable-new-dtags", OptVal::None, None)
            .long("enable-new-dtags", OptVal::None, None)
            .long("eh-frame-hdr", OptVal::None, None)
            .long("no-eh-frame-hdr", OptVal::None, None)
            .long("exclude-libs", OptVal::Required, None)
            .long("hash-style", OptVal::Required, None)
            .short('P', OptVal::Required, None)
            .long("depaudit", OptVal::Required, None);

        let cmdline = parser.parse_long_only(&args).unwrap();
        let output = cmdline.arg_value('o').unwrap();
        let mut inputs = Vec::new();

        for input in cmdline.positionals() {
            inputs.push(input.to_string());
        }

        if inputs.is_empty() {
            None
        } else {
            Some(Self {
                output: output.to_string(),
                args,
                inputs,
            })
        }
    }

    pub fn link(&self) {
        /* Run linker */
        let status =
            Command::new(&self.args[0]).args(self.args[1..].iter().filter(|x| !OPTION_BLACKLIST.contains(&x.as_str()))).arg("--no-relax").envs(std::env::vars()).status().unwrap();

        if let Some(code) = status.code() {
            if code != 0 {
                exit(code);
            }
        } else {
            exit(-1);
        }

        /* Merge metadata files */
        let mut output = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(format!("{}.{}", self.output, EXTENSION)).unwrap();

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
    fn test_wrapper1() {
        let wrapper = LdWrapper::from_cmdline(vec![
            "collect2".to_string(),
            "-plugin".to_string(),
            "/riscv/libexec/gcc/riscv64-unknown-linux-gnu/12.2.0/liblto_plugin.so".to_string(),
            "-plugin-opt=/riscv/libexec/gcc/riscv64-unknown-linux-gnu/12.2.0/lto-wrapper".to_string(),
            "-plugin-opt=-fresolution=/tmp/cc0yLsBM.res".to_string(),
            "-plugin-opt=-pass-through=-lgcc".to_string(),
            "-plugin-opt=-pass-through=-lgcc_s".to_string(),
            "-plugin-opt=-pass-through=-lc".to_string(),
            "-plugin-opt=-pass-through=-lgcc".to_string(),
            "-plugin-opt=-pass-through=-lgcc_s".to_string(),
            "--sysroot=/riscv/sysroot".to_string(),
            "--eh-frame-hdr".to_string(),
            "-melf64lriscv".to_string(),
            "-dynamic-linker".to_string(),
            "/lib/ld-linux-riscv64-lp64d.so.1".to_string(),
            "/riscv/sysroot/usr/lib/crt1.o".to_string(),
            "/riscv/lib/gcc/riscv64-unknown-linux-gnu/12.2.0/crti.o".to_string(),
            "/riscv/lib/gcc/riscv64-unknown-linux-gnu/12.2.0/crtbegin.o".to_string(),
            "-L/riscv/lib/gcc/riscv64-unknown-linux-gnu/12.2.0".to_string(),
            "-L/riscv/lib/gcc/riscv64-unknown-linux-gnu/12.2.0/../../../../riscv64-unknown-linux-gnu/lib".to_string(),
            "-L/riscv/sysroot/lib".to_string(),
            "-L/riscv/sysroot/usr/lib".to_string(),
            "/tmp/cckYZQFo.o".to_string(),
            "-lgcc".to_string(),
            "--push-state".to_string(),
            "--as-needed".to_string(),
            "-lgcc_s".to_string(),
            "--pop-state".to_string(),
            "-lc".to_string(),
            "-lgcc".to_string(),
            "--push-state".to_string(),
            "--as-needed".to_string(),
            "-lgcc_s".to_string(),
            "--pop-state".to_string(),
            "/riscv/lib/gcc/riscv64-unknown-linux-gnu/12.2.0/crtend.o".to_string(),
            "/riscv/lib/gcc/riscv64-unknown-linux-gnu/12.2.0/crtn.o".to_string(),
        ])
        .unwrap();
        println!("{:#?}", wrapper);
    }
}
