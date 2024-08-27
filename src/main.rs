extern crate rustbin;

use core::str;
use std::{env, fs::{File, OpenOptions}, io::{stdout, BufWriter, Write}, path::{Path, PathBuf}, process::ExitCode};

use clap::{ArgAction, Parser, ValueEnum};
use rustbin::{parse_file, pe::{ser::{full::FullPeImage, min::MinPeImage}, PeImage}, ParseAs, ParsedAs};

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

    #[arg(short, long, help="Level of data returned.", default_value = "display")]
    level: OutputLevel,

    #[arg(num_args(0..), short='x', long, action=ArgAction::Append, help="Excluded portions/sections.", default_value = "relocs")]
    exclude: Vec<ExcludeOptions>,
}


#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
enum OutputFormat {
    #[cfg(feature = "json")]
    JSON,

    #[default]
    TEXT,
}


#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputLevel {
    ///Only a minimal set of header fields.
    Minimal,

    ////Select all fields but skip field metadata.
    //ValueOnly,

    ////Show metadata for only for sturcts (most), skip field metadata.
    //TopLevel,

    ////Show complete metadata.
    Full,

    ///Show impl Debug of headers (only TEXT mode)
    Debug,

    ///Use formatted Display (only TEXT mode).
    #[default]
    Display
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ExcludeOptions {
    Imports,
    Exports,
    #[default]
    Relocs,
    Resources,
}

impl std::fmt::Display for ExcludeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
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

    let Ok(parsed) = parse_file(f, ParseAs::PE) else {
        println!("Failed to parse as `PE`.");
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
            let mut min_pe = MinPeImage::from(&pe);
            exclude_min_pe_parts(&mut min_pe, &args.exclude);
            let jstr = serde_json::to_string_pretty(&min_pe).unwrap();
            writeln!(out, "{jstr}").unwrap();
        },

        #[cfg(feature="json")]
        (OutputFormat::JSON, OutputLevel::Full) => {
            let mut min_pe = FullPeImage::from(&pe);
            exclude_full_pe_parts(&mut min_pe, &args.exclude);
            let jstr = serde_json::to_string_pretty(&min_pe).unwrap();
            writeln!(out, "{jstr}").unwrap();
        },

        (OutputFormat::TEXT, OutputLevel::Debug) => { writeln!(out, "{pe:#?}").unwrap(); },
        (OutputFormat::TEXT, OutputLevel::Display) => { 
            let pe_text = format_pe_as_text(&pe, &args.exclude);
            writeln!(out, "{pe_text}").unwrap(); 
        },
        
        _ => {
            eprintln!("Unsupported combination {:?} + {:?}", args.format, args.level);
        },
    };

    ExitCode::SUCCESS
}


fn format_pe_as_text(pe: &PeImage, exludes: &Vec<ExcludeOptions>) -> String {
    let mut out_str = String::new();
    pe.format_basic_headers(&mut out_str).unwrap();
    pe.format_data_dirs(&mut out_str).unwrap();
    pe.format_sections(&mut out_str).unwrap();
    if !exludes.contains(&ExcludeOptions::Imports) && pe.has_imports() { pe.format_imports(&mut out_str).unwrap(); }
    if !exludes.contains(&ExcludeOptions::Exports) && pe.has_exports() { pe.format_exports(&mut out_str).unwrap(); }
    if !exludes.contains(&ExcludeOptions::Relocs) && pe.has_relocations() { pe.format_relocations(&mut out_str).unwrap(); }
    if !exludes.contains(&ExcludeOptions::Resources) && pe.has_rsrc() { pe.format_resource_tree(&mut out_str, &String::from("  "), 1).unwrap(); }
    
    return out_str;
}

fn exclude_min_pe_parts(pe: &mut MinPeImage, exludes: &Vec<ExcludeOptions>){
    for exclude in exludes {
        match exclude {
            ExcludeOptions::Imports => pe.import_directories = None,
            ExcludeOptions::Exports => pe.export_directory = None,
            ExcludeOptions::Relocs => pe.relocations = None,
            ExcludeOptions::Resources => pe.resources = None,
        }
    }
}

fn exclude_full_pe_parts(pe: &mut FullPeImage, exludes: &Vec<ExcludeOptions>){
    for exclude in exludes {
        match exclude {
            ExcludeOptions::Imports => pe.imports = None,
            ExcludeOptions::Exports => {}, //TODO
            ExcludeOptions::Relocs => {}, //TODO
            ExcludeOptions::Resources => {}, //TODO
        }
    }
}
