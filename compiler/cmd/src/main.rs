mod compile_bpf;
mod config;
mod document_parser;
mod export_types;

use anyhow::Result;
use clap::Parser;
use compile_bpf::*;
use config::{init_eunomia_workspace, CompileOptions};
use eunomia_rs::TempDir;

fn main() -> Result<()> {
    let args = CompileOptions::parse();

    let tmp_workspace = TempDir::new().unwrap();

    init_eunomia_workspace(&tmp_workspace)?;

    compile_bpf(&args, &tmp_workspace)?;

    tmp_workspace.close()?;

    if !args.subskeleton {
        pack_object_in_config(&args)?;
    }

    Ok(())
}
