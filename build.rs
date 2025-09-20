extern crate cbindgen;

use std::env;
use std::string::ParseError;
use cbindgen::{Config, ExportConfig, Language, ParseConfig};

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(Config{
            language: Language::C,
            cpp_compat: true,
            export: ExportConfig {
                include: vec!["ArgsBundle".parse().unwrap(), "ReturnValue".parse().unwrap(), "GeetestChallenge".parse().unwrap(), "GeetestResult".parse().unwrap(),"GeetestCS".parse().unwrap()],
                ..Default::default()
            },
            parse: ParseConfig {
                parse_deps: false,
                ..Default::default()
            },
            ..Default::default()
        })
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("bindings.h");
}