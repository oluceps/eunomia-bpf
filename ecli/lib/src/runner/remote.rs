use crate::{
    config::*,
    error::{EcliError, EcliResult},
    json_runner::handle_json,
    wasm_bpf_runner::wasm,
    wasm_bpf_runner::wasm::handle_wasm,
};

use async_trait::async_trait;
use eunomia_rs::TempDir;
use hyper::server::conn::Http;
use hyper::service::Service;
use log::info;
use openapi_client::models::ListGet200ResponseTasksInner;
use openapi_client::server::MakeService;
use openapi_client::{models::*, Api, ListGetResponse, StartPostResponse, StopPostResponse};
use std::marker::PhantomData;
use std::{collections::HashMap, fs::write};
use std::{io::Cursor, sync::Arc};
use swagger::auth::MakeAllowAllAuthenticator;
use swagger::ApiError;
pub use swagger::{AuthData, ContextBuilder, EmptyContext, Has, Push, XSpanIdString};
use tokio::sync::Mutex;
use tokio::{net::TcpListener, sync::oneshot::Receiver};

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};

pub type ClientContext = swagger::make_context_ty!(
    ContextBuilder,
    EmptyContext,
    Option<AuthData>,
    XSpanIdString
);

/// Builds an SSL implementation for Simple HTTPS from some hard-coded file names
pub async fn create(addr: String, https: bool, shutdown_rx: Receiver<()>) {
    let addr = addr.parse().expect("Failed to parse bind address");

    let server_data = Arc::new(tokio::sync::Mutex::new(ServerData::new()));

    let server = Server::new(server_data);

    let service = MakeService::new(server);

    let service = MakeAllowAllAuthenticator::new(service, "cosmo");

    #[allow(unused_mut)]
    let mut service =
        openapi_client::server::context::MakeAddContext::<_, EmptyContext>::new(service);

    if https {
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
        {
            let mut ssl = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
                .expect("Failed to create SSL Acceptor");

            // Server authentication
            ssl.set_private_key_file("examples/server-key.pem", SslFiletype::PEM)
                .expect("Failed to set private key");
            ssl.set_certificate_chain_file("examples/server-chain.pem")
                .expect("Failed to set certificate chain");
            ssl.check_private_key()
                .expect("Failed to check private key");

            let tls_acceptor = ssl.build();
            let tcp_listener = TcpListener::bind(&addr).await.unwrap();

            loop {
                if let Ok((tcp, _)) = tcp_listener.accept().await {
                    let ssl = Ssl::new(tls_acceptor.context()).unwrap();
                    let addr = tcp.peer_addr().expect("Unable to get remote address");
                    let service = service.call(addr);

                    tokio::spawn(async move {
                        let tls = tokio_openssl::SslStream::new(ssl, tcp).map_err(|_| ())?;
                        let service = service.await.map_err(|_| ())?;

                        // TODO: shutdown of https server
                        Http::new()
                            .serve_connection(tls, service)
                            .await
                            .map_err(|_| ())
                    });
                }
            }
        }
    } else {
        // Using HTTP
        hyper::server::Server::bind(&addr)
            .serve(service)
            .with_graceful_shutdown(async {
                shutdown_rx.await.ok();
            })
            .await
            .unwrap()
    }
}

use wasm_bpf_rs::handle::WasmProgramHandle;
use wasm_bpf_rs::pipe::ReadableWritePipe;
use wasm_bpf_rs::run_wasm_bpf_module_async;
use wasm_bpf_rs::Config;

#[derive(Clone)]
pub struct Server<C> {
    data: Arc<tokio::sync::Mutex<ServerData>>,
    marker: PhantomData<C>,
}

#[derive(Clone)]
pub struct ServerData {
    wasm_tasks: HashMap<usize, WasmProgram>,
    id_name_map: HashMap<usize, String>,
    global_count: usize,
}

type SafeWasmProgramHandle = Arc<Mutex<WasmProgramHandle>>;

#[derive(Clone)]
pub struct WasmProgram {
    handler: SafeWasmProgramHandle,
    log_msg: ReadableWritePipe<Cursor<Vec<u8>>>,
}

impl WasmProgram {
    fn new(handler: SafeWasmProgramHandle, log_msg: ReadableWritePipe<Cursor<Vec<u8>>>) -> Self {
        Self { handler, log_msg }
    }
}

impl ServerData {
    fn new() -> Self {
        Self {
            wasm_tasks: HashMap::new(),
            id_name_map: HashMap::new(),
            global_count: 0,
        }
    }
}

impl<C> Server<C> {
    pub fn new(data: Arc<Mutex<ServerData>>) -> Self {
        Server {
            data,
            marker: PhantomData,
        }
    }
}

#[allow(unused)]
pub async fn endpoint_start(data: ProgramConfigData) -> EcliResult<()> {
    match data.prog_type {
        ProgramType::JsonEunomia => handle_json(data),
        ProgramType::WasmModule => handle_wasm(data),
        ProgramType::Tar => Err(EcliError::BpfError(format!(
            "Transporting btf path data to remote is not implemented"
        ))),
        _ => unreachable!(),
    }
}

// server behavior not implemented

#[async_trait]
impl<C> Api<C> for Server<C>
where
    C: Has<XSpanIdString> + Send + Sync,
{
    /// Get list of running tasks
    async fn list_get(&self, context: &C) -> Result<ListGetResponse, ApiError> {
        let context = context.clone();
        info!("Recieved List request, but has not been implemented");
        info!("list_get() - X-Span-ID: {:?}", context.get().0.clone());
        // Err(ApiError("This server behavior not implemented".into()))
        Ok(ListGetResponse::ListOfRunningTasks(ListGet200Response {
            status: Some("unimplemented".into()),
            tasks: None,
        }))
    }

    /// Start a new task
    async fn start_post(
        &self,
        program_data_buf: Option<swagger::ByteArray>,
        program_type: Option<String>,
        btf_data: Option<swagger::ByteArray>,
        extra_params: Option<&Vec<String>>,
        context: &C,
    ) -> Result<StartPostResponse, ApiError> {
        let context = context.clone();
        info!("Recieved start command, but has not been implemented");
        info!(
            "start_post({:?}, {:?}, {:?}, {:?}) - X-Span-ID: {:?}",
            program_data_buf,
            program_type,
            btf_data,
            extra_params,
            context.get().0.clone()
        );

        let mut server_data = self.data.lock().await;

        let tmp_dir = TempDir::new();

        let tmp_data_dir = tmp_dir.map_err(|e| ApiError(e.to_string())).unwrap();

        // store btf_data
        let btf_data_file_path = tmp_data_dir.path().join("btf_data");
        if let Some(b) = btf_data {
            if write(&btf_data_file_path, b.as_slice()).is_err() {
                return Err(ApiError("Save btf data fail".into()));
            };
        };

        let btf_path: Option<String> = if btf_data_file_path.exists() {
            Some(btf_data_file_path.as_path().display().to_string())
        } else {
            None
        };

        let prog_type = match program_type.unwrap().as_str() {
            "JsonEunomia" => ProgramType::JsonEunomia,
            "Tar" => ProgramType::Tar,
            "WasmModule" => ProgramType::WasmModule,
            &_ => ProgramType::Undefine,
        };

        match prog_type {
            ProgramType::WasmModule => {
                let stdout = ReadableWritePipe::new_vec_buf();
                let stderr = ReadableWritePipe::new_vec_buf();
                let config = Config::new(
                    String::from("go-callback"),
                    String::from("callback-wrapper"),
                    Box::new(wasmtime_wasi::stdio::stdin()),
                    Box::new(stdout.clone()),
                    Box::new(stderr.clone()),
                );
                let empty_extra_arg = vec![String::default()];

                let args = extra_params.unwrap_or_else(|| &empty_extra_arg).as_slice();

                let (wasm_handle, _) =
                    run_wasm_bpf_module_async(&program_data_buf.unwrap().0, &args, config).unwrap();

                server_data.wasm_tasks.insert(
                    // server_data.global_count.clone(),
                    1,
                    WasmProgram::new(Arc::new(Mutex::new(wasm_handle)), stdout),
                );

                server_data.global_count += 1;
            }
            _ => unimplemented!(),
        }

        // endpoint_start(data).await;

        Ok(StartPostResponse::ListOfRunningTasks(ListGet200Response {
            status: Some("unimplemented".into()),
            tasks: None,
        }))
    }

    /// Stop a task by id or name
    async fn stop_post(
        &self,
        list_get200_response_tasks_inner: ListGet200ResponseTasksInner,
        context: &C,
    ) -> Result<StopPostResponse, ApiError> {
        let context = context.clone();
        info!("Recieved stop command, but has not been implemented");
        info!("stop with id: {:?}", &list_get200_response_tasks_inner.id);

        info!(
            "stop_post({:?}) - X-Span-ID: {:?}",
            list_get200_response_tasks_inner,
            context.get().0.clone()
        );

        match (
            list_get200_response_tasks_inner.id,
            list_get200_response_tasks_inner.name,
        ) {
            (Some(_), _) | (_, Some(_)) => (),
            _ => eprintln!("request not contained id or name of program"),
        };

        // Err(ApiError("This server behavior not implemented".into()))
        Ok(StopPostResponse::StatusOfStoppingTheTask(
            StopPost200Response {
                status: Some("unimplemented".into()),
            },
        ))
    }
}
