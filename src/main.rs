extern crate rustbin;

use std::{path::{Path, PathBuf}, env};

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    target: Option<String>,

    #[arg(short, long, value_enum, default_value_t = Default::default())]
    format: OutputFormat
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
enum OutputFormat {
    #[cfg(feature = "json")]
    JSON,

    #[default]
    TEXT,
}

fn main() {
    let args = Args::parse();

    println!("target: {:?}", args.target);
    println!("format: {:?}", args.format);

    let binpath: PathBuf;

    if let Some(target) = args.target{
        binpath = Path::new(&target).into();
    } else if cfg!(windows){
        binpath = env::current_exe().unwrap();
    } else {
        println!("Target is required.");
        return;
    }

    if !binpath.is_file() {
        println!("Target is not a file");
        return;
    }


}
