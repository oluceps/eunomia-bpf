mod compile_bpf;
mod config;
mod document_parser;
mod export_types;

use crate::config::init_eunomia_workspace;
use anyhow::Result;
use clap::Parser;
use compile_bpf::*;
use config::CompileOptions;

fn main() -> Result<()> {
    let args = CompileOptions::parse();
    init_eunomia_workspace()?;
    compile_bpf(&args)?;
    if !args.subskeleton {
        pack_object_in_config(&args)?;
    }
    Ok(())
}
