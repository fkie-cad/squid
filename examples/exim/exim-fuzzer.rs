use squid::Compiler;

fn main() {
    let mut compiler = Compiler::loader()
        .binary("./dist/exim")
        .search_path("./dist/lib")
        .ignore_missing_dependencies(true)
        .load()
        .unwrap();
}
