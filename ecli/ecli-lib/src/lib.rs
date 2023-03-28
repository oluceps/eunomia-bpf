//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
<<<<<<<< HEAD:ecli/client/src/main.rs
use clap::{Parser, Subcommand};
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::{process, thread};

mod utils;

use lib::{
    error::*,
    init_log,
    oci::{
        auth::{login, logout},
        pull, push,
    },
    runner::{client_action, run},
    ClientCmd, Signals, SIGINT,
|||||||| parent of 10743ce (chore: resolve conflict):ecli/src/main.rs
mod config;
mod error;
mod json_runner;
mod oci;
mod runner;
mod tar_reader;
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::{process, thread};
mod wasm_bpf_runner;
use clap::{Parser, Subcommand};
use env_logger::{Builder, Target};
use error::EcliResult;
use oci::{
    auth::{login, logout},
    pull, push,
========
pub mod config;
pub mod error;
pub mod json_runner;
pub mod oci;
pub mod runner;
pub mod tar_reader;
pub use runner::RemoteArgs;
pub use signal_hook::{consts::SIGINT, iterator::Signals};
pub use std::{process, thread};
pub mod wasm_bpf_runner;
pub use clap::{Parser, Subcommand};
pub use env_logger::{Builder, Target};
pub mod eunomia_bpf;
pub use error::EcliResult;
pub use oci::{
    auth::{login, logout},
    pull, push,
>>>>>>>> 10743ce (chore: resolve conflict):ecli/ecli-lib/src/lib.rs
};
<<<<<<<< HEAD:ecli/client/src/main.rs
use runner::run;
use std::process;
use std::thread;
|||||||| parent of 10743ce (chore: resolve conflict):ecli/src/main.rs
// use runner::start_server;
use runner::{client_action, run, start_server};
========
pub use runner::{client_action, run, start_server};
>>>>>>>> 10743ce (chore: resolve conflict):ecli/ecli-lib/src/lib.rs

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
// use runner::start_server;
use runner::{client_action, run, start_server};

/// ecli subcommands, including run, push, pull, login, logout.
#[derive(Subcommand)]
pub enum Action {
    Run {
        /// run without cache
        #[arg(long, short = 'n', default_value_t = false)]
        no_cache: bool,
        /// json output format
        #[arg(long, short = 'j', default_value_t = false)]
        json: bool,
        /// program path or url
        #[arg(allow_hyphen_values = true)]
        prog: Vec<String>,
    },

    #[clap(name = "client", about = "Client operations")]
    Client(ClientCmd),

    /// push wasm or oci image to registry
    Push {
        #[arg(long, short, default_value_t = ("app.wasm").to_string())]
        module: String,
        #[arg()]
        image: String,
    },

    /// pull oci image from registry
    Pull {
        /// wasm module url
        #[arg(short, long, default_value_t = ("app.wasm").to_string())]
        output: String,
        /// oci image url
        #[arg()]
        image: String,
    },

    /// login to oci registry
    Login {
        #[arg()]
        url: String,
    },

    /// logout from registry
    Logout {
        #[arg()]
        url: String,
    },
}
fn init_log() {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);
    builder.init();
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
