use crate::config::*;
use async_trait::async_trait;
use eunomia_rs::TempDir;
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
use tokio::sync::oneshot::Receiver;
use tokio::sync::Mutex;

pub async fn create(addr: String, _https: bool, shutdown_rx: Receiver<()>) {
    let addr = addr.parse().expect("Failed to parse bind address");

    let server_data = Arc::new(Mutex::new(ServerData::new()));

    let server = Server::new(server_data);

    let service = MakeService::new(server);

    let service = MakeAllowAllAuthenticator::new(service, "cosmo");

    let service = openapi_client::server::context::MakeAddContext::<_, EmptyContext>::new(service);

    // Using HTTP
    hyper::server::Server::bind(&addr)
        .serve(service)
        .with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        })
        .await
        .unwrap()
}

use wasm_bpf_rs::handle::WasmProgramHandle;
use wasm_bpf_rs::pipe::ReadableWritePipe;
use wasm_bpf_rs::run_wasm_bpf_module_async;
use wasm_bpf_rs::Config;

#[derive(Clone)]
pub struct Server<C> {
    data: Arc<Mutex<ServerData>>,
    marker: PhantomData<C>,
}

#[derive(Clone)]
pub struct ServerData {
    wasm_tasks: HashMap<usize, WasmProgram>,
    id_name_map: HashMap<usize, String>,
    global_count: usize,
}

#[derive(Clone)]
pub struct WasmProgram {
    handler: Arc<Mutex<WasmProgramHandle>>,

    #[allow(dead_code)]
    log_msg: LogMsg,
}

#[derive(Clone)]
#[allow(unused)]
struct LogMsg {
    stdout: ReadableWritePipe<Cursor<Vec<u8>>>,
    stderr: ReadableWritePipe<Cursor<Vec<u8>>>,
}

impl WasmProgram {
    fn new(handler: WasmProgramHandle, log_msg: LogMsg) -> Self {
        Self {
            handler: Arc::new(Mutex::new(handler)),
            log_msg,
        }
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

#[async_trait]
impl<C> Api<C> for Server<C>
where
    C: Has<XSpanIdString> + Send + Sync,
{
    /// Get list of running tasks
    async fn list_get(&self, context: &C) -> Result<ListGetResponse, ApiError> {
        let context = context.clone();
        info!("Recieved List request");
        info!("list_get() - X-Span-ID: {:?}", context.get().0.clone());

        let server_data = self.data.lock().await;

        let id_and_name: Vec<ListGet200ResponseTasksInner> = server_data
            .id_name_map
            .clone()
            .into_iter()
            .map(|(id, name)| ListGet200ResponseTasksInner {
                id: Some(id as i32),
                name: Some(name),
            })
            .collect();

        Ok(ListGetResponse::ListOfRunningTasks(ListGet200Response {
            status: Some("Ok".into()),
            tasks: Some(id_and_name),
        }))
    }

    /// Start a new task
    async fn start_post(
        &self,
        program_data_buf: Option<swagger::ByteArray>,
        program_type: Option<String>,
        program_name: Option<String>,
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

        let _btf_path: Option<String> = if btf_data_file_path.exists() {
            Some(btf_data_file_path.as_path().display().to_string())
        } else {
            None
        };

        let prog_type = program_type.unwrap().parse::<ProgramType>().unwrap();
        let id = server_data.global_count.clone();

        match prog_type {
            ProgramType::WasmModule => {
                let stdout = ReadableWritePipe::new_vec_buf();
                let stderr = ReadableWritePipe::new_vec_buf();
                let config = Config {
                    callback_export_name: String::from("go-callback"),
                    wrapper_module_name: String::from("callback-wrapper"),
                    ..Default::default()
                };
                //     String::from("go-callback"),
                //     String::from("callback-wrapper"),
                //     // Box::new(wasmtime_wasi::stdio::stdin()),
                //     // Box::new(stdout.clone()),
                //     // Box::new(stderr.clone()),
                //     ..Default::default(),
                // );
                let empty_extra_arg = vec![String::default()];

                let args = extra_params.unwrap_or_else(|| &empty_extra_arg).as_slice();

                let (wasm_handle, _) =
                    run_wasm_bpf_module_async(&program_data_buf.unwrap().0, &args, config).unwrap();

                server_data
                    .wasm_tasks
                    .insert(id, WasmProgram::new(wasm_handle, LogMsg { stdout, stderr }));

                server_data
                    .id_name_map
                    .insert(id, program_name.unwrap_or("NamelessProg".to_string()));

                server_data.global_count += 1;
            }
            _ => unimplemented!(),
        }

        Ok(StartPostResponse::ListOfRunningTasks(ListGet200Response {
            status: Some("Ok".into()),
            tasks: Some(vec![ListGet200ResponseTasksInner {
                id: Some(id as i32),
                name: None,
            }]),
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

        let stop_rsp = |s: &str| {
            Ok(StopPostResponse::StatusOfStoppingTheTask(
                StopPost200Response {
                    status: Some(s.into()),
                },
            ))
        };

        let id = list_get200_response_tasks_inner.id.unwrap();

        let mut server_data = self.data.lock().await;

        let task = server_data
            .wasm_tasks
            .remove(&(id.checked_abs().unwrap() as usize));

        if let Some(t) = task {
            let handler = t.handler.lock().await;

            if handler.terminate().is_ok() {
                server_data
                    .id_name_map
                    .remove(&(id.checked_abs().unwrap() as usize));
                return stop_rsp("successful terminated");
            }
            return stop_rsp("fail to terminate");
        }
        return stop_rsp("program with specified id not found");
    }
}
