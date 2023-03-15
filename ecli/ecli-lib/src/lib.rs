//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
pub mod config;
pub mod error;
pub mod json_runner;
pub mod oci;
pub mod runner;
pub mod tar_reader;
pub use signal_hook::{consts::SIGINT, iterator::Signals};
pub use std::{process, thread};
pub mod wasm_bpf_runner;
pub use clap::{Parser, Subcommand};
pub use env_logger::{Builder, Target};
pub use error::EcliResult;
pub use oci::{
    auth::{login, logout},
    pull, push,
};

#[derive(Subcommand)]
pub enum Action {
    Run {
        #[arg(long, short = 'n')]
        no_cache: Option<bool>,
        #[arg(long, short = 'j')]
        json: Option<bool>,
        #[arg(allow_hyphen_values = true)]
        prog: Vec<String>,
    },

    #[clap(name = "server", about = "start a server to control the ebpf programs")]
    Server {
        #[arg(short, long)]
        config: Option<String>,
        #[arg(short, long, default_value = "false")]
        secure: bool,
        #[clap(short, long, help = "server port", default_value = "8527")]
        port: u16,
        #[arg(short, long, default_value = "127.0.0.1")]
        addr: String,
    },

    #[clap(name = "client", about = "Client operations")]
    Client(ClientCmd),

    Push {
        #[arg(long, short, default_value_t = ("app.wasm").to_string())]
        module: String,
        #[arg()]
        image: String,
    },

    Pull {
        #[arg(short, long, default_value_t = ("app.wasm").to_string())]
        output: String,
        #[arg()]
        image: String,
    },

    Login {
        #[arg()]
        url: String,
    },

    Logout {
        #[arg()]
        url: String,
    },
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Parser)]
pub struct ClientCmd {
    #[clap(subcommand)]
    pub cmd: ClientSubCommand,

    #[clap(flatten)]
    pub opts: ClientOpts,
}

#[derive(Parser)]
pub enum ClientSubCommand {
    #[clap(name = "start", about = "start an ebpf programs on endpoint")]
    Start(StartCommand),

    #[clap(name = "stop", about = "stop running tasks on endpoint with id")]
    Stop(StopCommand),

    #[clap(name = "list", about = "list the ebpf programs running on endpoint")]
    List,
}

#[derive(Parser)]
pub struct ClientOpts {
    #[clap(short, long, help = "endpoint", default_value = "127.0.0.1")]
    pub endpoint: String,

    #[clap(short, long, help = "enpoint port", default_value = "8527")]
    pub port: u16,

    #[clap(short, long, help = "transport with https", default_value = "false")]
    pub secure: bool,
}

#[derive(Parser)]
pub struct StartCommand {
    #[clap(required = true)]
    pub prog: Vec<String>,
    #[clap(long)]
    pub extra_args: Option<Vec<String>>,
}

#[derive(Parser)]
pub struct StopCommand {
    #[clap(required = true)]
    pub id: Vec<i32>,
}

pub fn init_log() {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);
    builder.init();
}

use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::ptr::null_mut;

use crate::config::ExportFormatType;
use crate::config::ProgramConfigData;
use crate::error::EcliError;

pub mod eunomia_bpf;

pub use eunomia_bpf::export_format_type_EXPORT_JSON;
pub use eunomia_bpf::export_format_type_EXPORT_PLANT_TEXT;
pub use eunomia_bpf::load_and_attach_eunomia_skel;
pub use eunomia_bpf::open_eunomia_skel_from_json_package_with_args;
pub use eunomia_bpf::parse_args_to_json_config;
pub use eunomia_bpf::wait_and_poll_events_to_handler;

unsafe extern "C" fn handler(
    _ctx: *mut ::std::os::raw::c_void,
    event: *const ::std::os::raw::c_char,
    _size: eunomia_bpf::size_t,
) {
    println!("{}", CStr::from_ptr(event).to_string_lossy().to_string());
}

pub fn handle_json(conf: ProgramConfigData) -> EcliResult<()> {
    let json_data = CString::new(conf.program_data_buf.as_slice())
        .map_err(|e| EcliError::Other(e.to_string()))?;
    let mut extra_arg_raw = vec![];
    let mut cstr_vec = vec![];
    let arg = CString::new(conf.url.as_bytes()).unwrap();
    extra_arg_raw.push(arg.as_ptr() as *mut c_char);
    for arg in conf.extra_arg {
        cstr_vec.push(CString::new(arg.as_bytes()).unwrap());
        extra_arg_raw.push(cstr_vec.last().unwrap().as_ptr() as *mut c_char);
    }
    let bpf = unsafe {
        open_eunomia_skel_from_json_package_with_args(
            json_data.as_ptr() as *const c_char,
            extra_arg_raw.as_mut_ptr(),
            extra_arg_raw.len() as i32,
            match conf.btf_path {
                Some(path) => path.as_ptr() as *mut c_char,
                _ => std::ptr::null_mut(),
            },
        )
    };
    if bpf.is_null() {
        return Err(EcliError::BpfError("open bpf from json fail".to_string()));
    }

    unsafe {
        if load_and_attach_eunomia_skel(bpf) < 0 {
            return Err(EcliError::BpfError(
                "load and attach ebpf program failed".to_string(),
            ));
        }

        if wait_and_poll_events_to_handler(
            bpf,
            match conf.export_format_type {
                ExportFormatType::ExportJson => export_format_type_EXPORT_JSON,
                ExportFormatType::ExportPlantText => export_format_type_EXPORT_PLANT_TEXT,
            },
            Some(handler),
            null_mut::<c_void>(),
        ) < 0
        {
            return Err(EcliError::BpfError(
                "wait and poll to handler failed".to_string(),
            ));
        }
    }

    Ok(())
}
