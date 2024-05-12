extern crate rustbin;

use core::str;
use std::{env, fs::{File, OpenOptions}, io::{stdout, BufReader, BufWriter, Write}, path::{Path, PathBuf}, process::ExitCode};

use clap::{ArgAction, Parser, ValueEnum};
use rustbin::{parse_file, pe::ser::min::MinPeImage, ParseAs, ParsedAs};

/*
#[derive(Debug, Error)]
enum CliError {
    #[error("Failed to create JSON from Source")]
    JsonError(serde_json::Error),

    #[error("Invalid combimation: {:?} + {:?}", .0, .1)]
    OptionsError(OutputFormat, OutputLevel)

}
*/

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    target: Option<String>,

    #[arg(short, long, value_enum, default_value_t = Default::default(), help="Output format")]
    format: OutputFormat,

    #[arg(short, long, help="Output file. [default: stdout]")]
    output: Option<String>,

    #[arg(short, long, help="Level of data returned.")]
    level: OutputLevel,

    #[arg(num_args(0..), short='x', long, action=ArgAction::Append, help="Excluded portions/sections.")]
    exclude: Vec<ExcludeOptions>,
}


#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
enum OutputFormat {
    #[cfg(feature = "json")]
    JSON,

    #[default]
    TEXT,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputLevel {
    ///Only a minimal set of header fields.
    Minimal,

    ////Select all fields but skip field metadata.
    //ValueOnly,

    ////Show metadata for only for sturcts (most), skip field metadata.
    //TopLevel,

    ////Show complete metadata.
    //Full,

    ///Show impl Debug of headers (only TEXT mode)
    Debug,

    ///Use formatted Display (only TEXT mode).
    Display
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ExcludeOptions {
    Imports,
    Exports,
    Relocs,
    Resources,
}

fn main() -> ExitCode {
    let args = Args::parse();

    println!("target: {:?}", args.target);
    println!("format: {:?}", args.format);
    println!("exclude: {:?}", args.exclude);

    let binpath:PathBuf = if let Some(target) = args.target{
        Path::new(&target).into()
    } else if cfg!(windows){
        env::current_exe().unwrap()
    } else {
        println!("Target is required.");
        return ExitCode::from(1);
    };

    if !binpath.is_file() {
        println!("Target is not a file");
        return ExitCode::from(2);
    }

    println!("BinPath: {binpath:?}");

    let Ok(f) = OpenOptions::new()
            .read(true)
            .open(binpath)
        else {
            println!("Failed to open file in read mode.");
            return ExitCode::from(3);
        };
        
    let mut reader = BufReader::new(f);

    let Ok(parsed) = parse_file(&mut reader, ParseAs::PE) else {
        println!("Failed to parsed as `PE`.");
        return ExitCode::from(4);
    };

    let ParsedAs::PE(pe) = parsed;

    let mut out = BufWriter::new(match args.output {
        Some(ref x) => Box::new(File::create(&Path::new(x)).unwrap()) as Box<dyn Write>,
        None => Box::new(stdout()) as Box<dyn Write>,
    } as Box<dyn Write>);

    match (args.format, args.level){
        #[cfg(feature="json")]
        (OutputFormat::JSON, OutputLevel::Minimal) => {
            let min_pe = MinPeImage::from(&pe);
            let jstr = serde_json::to_string_pretty(&min_pe).unwrap();
            writeln!(out, "{jstr}").unwrap();
        },

        (OutputFormat::TEXT, OutputLevel::Debug) => { writeln!(out, "{pe:#?}").unwrap(); },
        (OutputFormat::TEXT, OutputLevel::Display) => { writeln!(out, "{pe}").unwrap(); },
        
        _ => {
            eprintln!("Unsupported combination {:?} + {:?}", args.format, args.level);
        },
    };

    ExitCode::SUCCESS
}
