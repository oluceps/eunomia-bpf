use crate::eunomia_bpf::{destroy_eunomia_skel, eunomia_bpf};
use crate::{config::*, json_runner::json_handler, EcliResult};
use async_trait::async_trait;
use eunomia_rs::TempDir;
use log::info;
use openapi_client::models::ListGet200ResponseTasksInner;
use openapi_client::server::MakeService;
use openapi_client::{models::*, Api, ListGetResponse, StartPostResponse, StopPostResponse};
use std::marker::PhantomData;
use std::ptr::NonNull;
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
    wasm_tasks: HashMap<usize, WasmModuleProgram>,
    json_tasks: HashMap<usize, JsonEunomiaProgram>,
    prog_info: HashMap<usize, (String, ProgramType)>,
    global_count: usize,
}

struct EunomiaBpfPtr(NonNull<eunomia_bpf>);

unsafe impl Send for EunomiaBpfPtr {}
unsafe impl Sync for EunomiaBpfPtr {}

impl Drop for EunomiaBpfPtr {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

impl EunomiaBpfPtr {
    fn from_raw_ptr(p: *mut eunomia_bpf) -> Self {
        let ptr = NonNull::<eunomia_bpf>::new(p).expect("ptr of `eunomia_bpf` is null!");
        Self(ptr)
    }

    fn get_raw(&mut self) -> *mut eunomia_bpf {
        NonNull::as_ptr(self.0)
    }

    fn terminate(&mut self) -> EcliResult<()> {
        unsafe { destroy_eunomia_skel(self.get_raw()) }
        Ok(())
    }
}

#[derive(Clone)]
pub struct WasmModuleProgram {
    handler: Arc<Mutex<WasmProgramHandle>>,

    #[allow(dead_code)]
    log_msg: LogMsg,
}

#[derive(Clone)]
pub struct JsonEunomiaProgram {
    ptr: Arc<Mutex<EunomiaBpfPtr>>,

    #[allow(dead_code)]
    log_msg: LogMsg,
}

#[derive(Clone)]
#[allow(unused)]
struct LogMsg {
    stdout: ReadableWritePipe<Cursor<Vec<u8>>>,
    stderr: ReadableWritePipe<Cursor<Vec<u8>>>,
}

impl WasmModuleProgram {
    fn new(handler: WasmProgramHandle, log_msg: LogMsg) -> Self {
        Self {
            handler: Arc::new(Mutex::new(handler)),
            log_msg,
        }
    }
}

impl JsonEunomiaProgram {
    fn new(ptr: EunomiaBpfPtr, log_msg: LogMsg) -> Self {
        Self {
            ptr: Arc::new(Mutex::new(ptr)),
            log_msg,
        }
    }

    async fn stop(self) -> EcliResult<()> {
        self.ptr.lock_owned().await.terminate()
    }
}

impl ServerData {
    fn new() -> Self {
        Self {
            wasm_tasks: HashMap::new(),
            json_tasks: HashMap::new(),
            prog_info: HashMap::new(),
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

struct StartupElements<'a> {
    id: usize,
    program_name: String,
    program_data_buf: Vec<u8>,
    extra_params: &'a Vec<String>,
}

impl<'a> StartupElements<'a> {
    fn new(
        id: usize,
        program_name: Option<String>,
        program_data_buf: Option<swagger::ByteArray>,
        extra_params: Option<&'a Vec<String>>,
    ) -> Self {
        let elements = Self {
            id,
            program_name: program_name.unwrap_or("NamelessProg".to_string()),
            program_data_buf: program_data_buf.unwrap().0,
            extra_params: extra_params.unwrap(),
        };

        return elements;
    }

    fn _validate(&self) -> EcliResult<()> {
        match *self.program_data_buf {
            _ => Ok(()),
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

        let id_and_info: Vec<ListGet200ResponseTasksInner> = server_data
            .prog_info
            .clone()
            .into_iter()
            .map(|(id, info)| ListGet200ResponseTasksInner {
                id: Some(id as i32),
                name: Some(format!("{} - {:?}", info.0, info.1)),
            })
            .collect();

        Ok(ListGetResponse::ListOfRunningTasks(ListGet200Response {
            status: Some("Ok".into()),
            tasks: Some(id_and_info),
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

        let prog_type = program_type.unwrap().parse::<ProgramType>().unwrap();

        let id = server_data.global_count.clone();

        let startup_elem = StartupElements::new(id, program_name, program_data_buf, extra_params);

        let start_result = match prog_type {
            ProgramType::WasmModule => wasm_start(startup_elem, &mut server_data),

            ProgramType::JsonEunomia => json_start(startup_elem, &mut server_data),

            ProgramType::Tar => unimplemented!(), // tar_start(startup_elem, btf_data, &mut server_data),

            _ => unreachable!(),
        };

        start_result.map(|id| {
            StartPostResponse::ListOfRunningTasks(ListGet200Response {
                status: Some("Ok".into()),
                tasks: Some(vec![ListGet200ResponseTasksInner {
                    id: Some(id),
                    name: None,
                }]),
            })
        })
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

        let prog_info = server_data
            .prog_info
            .remove(&(id.checked_abs().unwrap() as usize));

        if prog_info.is_none() {
            return Err(ApiError("program with id not found".to_string()));
        }

        let prog_type = prog_info.clone().unwrap().1;

        match prog_type {
            ProgramType::JsonEunomia => {
                let task = server_data
                    .json_tasks
                    .remove(&(id.checked_abs().unwrap() as usize));
                if let Some(t) = task {
                    if t.stop().await.is_ok() {
                        return stop_rsp(
                            format!("{} successful terminated", &prog_info.unwrap().0).as_str(),
                        );
                    };
                }
                return stop_rsp("fail to terminate");
            }
            ProgramType::WasmModule => {
                let task = server_data
                    .wasm_tasks
                    .remove(&(id.checked_abs().unwrap() as usize));

                if let Some(t) = task {
                    let handler = t.handler.lock().await;

                    if handler.terminate().is_ok() {
                        server_data
                            .prog_info
                            .remove(&(id.checked_abs().unwrap() as usize));
                        return stop_rsp("successful terminated");
                    }
                    return stop_rsp("fail to terminate");
                }
            }
            _ => unimplemented!(),
        }

        return Err(ApiError("program with id not found".to_string()));
    }
}

fn json_start(
    startup_elem: StartupElements,
    server_data: &mut ServerData,
) -> Result<i32, ApiError> {
    let StartupElements {
        id,
        program_name,
        program_data_buf,
        extra_params,
    } = startup_elem;

    let data = ProgramConfigData {
        url: String::default(),
        use_cache: false,
        btf_path: None,
        program_data_buf,
        extra_arg: extra_params.clone(),
        prog_type: ProgramType::JsonEunomia,
        export_format_type: ExportFormatType::ExportPlantText,
    };

    let stdout = ReadableWritePipe::new_vec_buf();
    let stderr = ReadableWritePipe::new_vec_buf();
    let ptr = EunomiaBpfPtr::from_raw_ptr(json_handler(data).unwrap());
    let prog = JsonEunomiaProgram::new(ptr, LogMsg { stdout, stderr });
    server_data.json_tasks.insert(id, prog);
    server_data
        .prog_info
        .insert(id, (program_name, ProgramType::JsonEunomia));

    server_data.global_count += 1;
    Ok(id as i32)
}

fn wasm_start(
    startup_elem: StartupElements,
    server_data: &mut ServerData,
) -> Result<i32, ApiError> {
    let StartupElements {
        id,
        program_name,
        program_data_buf,
        extra_params,
    } = startup_elem;

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

    let (wasm_handle, _) =
        run_wasm_bpf_module_async(&program_data_buf, &extra_params, config).unwrap();

    server_data.wasm_tasks.insert(
        id,
        WasmModuleProgram::new(wasm_handle, LogMsg { stdout, stderr }),
    );

    server_data
        .prog_info
        .insert(id, (program_name, ProgramType::WasmModule));

    server_data.global_count += 1;
    Ok(id as i32)
}

#[allow(unused)]
fn tar_start(
    startup_elem: StartupElements,
    btf_data: Option<swagger::ByteArray>,
    server_data: &mut ServerData,
) -> Result<i32, ApiError> {
    let StartupElements {
        id,
        program_name,
        program_data_buf,
        extra_params,
    } = startup_elem;

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
    Err(ApiError("not implemented".to_string()))
}
