//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
mod config;
mod error;
mod json_runner;
mod oci;
mod runner;
mod tar_reader;
mod wasm_bpf_runner;
use clap::{Parser, Subcommand};
use env_logger::{Builder, Target};

/// ecli subcommands, including run, push, pull, login, logout.
#[derive(Subcommand)]
pub enum Action {
    /// run ebpf program
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
        /// wasm module path
        #[arg(long, short, default_value_t = ("app.wasm").to_string())]
        module: String,
        /// oci image path
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
        /// oci login url
        #[arg()]
        url: String,
    },
    /// logout from registry
    Logout {
        /// oci logout url
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