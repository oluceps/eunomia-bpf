use actix_web::error::ErrorBadRequest;
use actix_web::{get, post};
use actix_web::{web, App, HttpServer, Responder, Result};

use crate::config::*;
use crate::runner::models::{ListGet200ResponseTasksInner, LogPostRequest};
use crate::runner::response::*;
use crate::runner::utils::*;
use log::info;
use tokio::sync::oneshot::Receiver;
use tokio::sync::Mutex;

struct AppState {
    server: Mutex<ServerData>,
}

impl AppState {
    fn new() -> Self {
        Self {
            server: Mutex::new(ServerData::new()),
        }
    }
}

pub async fn create(
    dst: crate::runner::Dst,
    _https: bool,
    _shutdown_rx: Receiver<()>,
) -> std::io::Result<()> {
    let state = web::Data::new(AppState::new());

    HttpServer::new(move || {
        // move counter into the closure
        App::new()
            .app_data(state.clone()) // <- register the created data
            .service(list_get)
            .service(start_post)
            .service(stop_post)
            .service(log_post)
    })
    .bind(dst.to_addrs())
    .unwrap()
    .run()
    .await
}

/// Get list of running tasks
#[get("/list")]
async fn list_get(data: web::Data<ServerData>) -> Result<impl Responder> {
    // let context = context.clone();
    info!("Recieved List request");
    // info!("list_get() - X-Span-ID: {:?}", context.get().0.clone());

    let server_data = data;

    let listed_info: Vec<ListGet200ResponseTasksInner> = server_data.list_all_task();

    Ok(ListGetResponse::gen_rsp(listed_info))
}

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StartReq {
    pub program_data_buf: Option<swagger::ByteArray>,
    pub program_type: Option<String>,
    pub program_name: Option<String>,
    pub btf_data: Option<swagger::ByteArray>,
    pub extra_params: Option<Vec<String>>,
}

/// Start a new task
#[post("/start")]
async fn start_post(
    data: web::Data<AppState>,
    start_req: web::Json<StartReq>,
) -> Result<impl Responder> {
    // let context = context.clone();
    info!("Recieved start command, but has not fully been implemented");

    let startup_elem = start_req.0;

    let mut server_data = data.server.lock().await;

    let prog_type = startup_elem
        .program_type
        .clone()
        .unwrap()
        .parse::<ProgramType>()
        .unwrap();

    let start_result = match prog_type {
        ProgramType::WasmModule => server_data.wasm_start(startup_elem),

        ProgramType::JsonEunomia => Ok(-1), // json_start(startup_elem, &mut server_data),

        ProgramType::Tar => unimplemented!(), // tar_start(startup_elem, btf_data, &mut server_data),

        _ => unreachable!(),
    };

    start_result
        .map(|id| StartPostResponse::gen_rsp(id))
        .map_err(|_e| actix_web::error::ErrorBadRequest(""))
}

/// Stop a task by id or name
#[post("/stop")]
async fn stop_post(
    data: web::Data<AppState>,
    list_get200_response_tasks_inner: web::Json<ListGet200ResponseTasksInner>,
) -> Result<impl Responder> {
    // let context = context.clone();
    info!("Recieved stop command, but has not fully implemented");
    info!("stop with id: {:?}", &list_get200_response_tasks_inner.id);

    // info!(
    //     "stop_post({:?}) - X-Span-ID: {:?}",
    //     list_get200_response_tasks_inner,
    //     context.get().0.clone()
    // );

    let id = list_get200_response_tasks_inner.id.unwrap();

    let mut server_data = data.server.lock().await;

    let prog_info = server_data
        .prog_info
        .remove(&(id.checked_abs().unwrap() as usize));

    if prog_info.is_none() {
        return Ok(StopPostResponse::gen_rsp("NotFound"));
    }

    server_data
        .stop_prog(id, prog_info.unwrap())
        .await
        .map_err(|_e| actix_web::error::ErrorBadRequest(""))
}

/// get log
#[get("/log")]
async fn log_post(
    data: web::Data<AppState>,
    log_post_request: web::Json<LogPostRequest>,
) -> Result<impl Responder> {
    let id = log_post_request.id.unwrap().checked_abs().unwrap() as usize;

    let mut server_data = data.server.lock().await;

    let prog_type = server_data.get_type_of(id);

    if prog_type.is_none() {
        return Err(ErrorBadRequest(""));
    }

    let (out, err) = match prog_type.unwrap() {
        ProgramType::WasmModule => {
            let prog = server_data.wasm_tasks.get_mut(&id).unwrap();

            let out = prog.log_msg.get_stdout();
            let err = prog.log_msg.get_stderr();

            (out, err)
        }
        _ => unimplemented!(),
    };

    Ok(LogPostResponse::gen_rsp(Some(out), Some(err)))
}