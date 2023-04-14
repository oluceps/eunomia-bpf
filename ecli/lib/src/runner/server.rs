use std::io::Cursor;
use std::thread;
use std::time::{Duration, Instant};

use actix_web::{get, post, HttpRequest};
use actix_web::{web, App, HttpServer, Responder, Result};
use actix_web_actors::ws;

use crate::config::*;
use crate::runner::models::ListGet200ResponseTasksInner;
use crate::runner::response::*;
use crate::runner::utils::*;
use log::info;
use std::sync::Mutex;

pub struct AppState {
    server: Mutex<ServerData>,
}

impl AppState {
    fn new() -> Self {
        Self {
            server: Mutex::new(ServerData::new()),
        }
    }
}

pub async fn create(dst: crate::runner::Dst, _https: bool) -> std::io::Result<()> {
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
async fn list_get(data: web::Data<AppState>) -> Result<impl Responder> {
    // let context = context.clone();
    info!("Recieved List request");
    // info!("list_get() - X-Span-ID: {:?}", context.get().0.clone());

    let server_data = data.server.lock().unwrap();

    let listed_info: Vec<ListGet200ResponseTasksInner> = server_data.list_all_task();

    Ok(web::Json(ListGetResponse::gen_rsp(listed_info)))
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

    let mut server_data = data.server.lock().unwrap();

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

    Ok(web::Json(
        start_result
            .map(|id| StartPostResponse::gen_rsp(id))
            .unwrap(),
    ))
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

    let id = list_get200_response_tasks_inner.id.unwrap();

    let mut server_data = data.server.lock().unwrap();

    let prog_info = server_data
        .prog_info
        .remove(&(id.checked_abs().unwrap() as usize));

    if prog_info.is_none() {
        return Ok(web::Json(StopPostResponse::gen_rsp("NotFound")));
    }

    Ok(web::Json(
        server_data.stop_prog(id, prog_info.unwrap()).await.unwrap(),
    ))
}
trait GetLog {
    fn get_wasm_log(&self, id: usize) -> Cursor<Vec<u8>>;
}

impl GetLog for web::Data<AppState> {
    fn get_wasm_log(&self, id: usize) -> Cursor<Vec<u8>> {
        self.server
            .lock()
            .unwrap()
            .wasm_tasks
            .get(&id)
            .unwrap()
            .log_msg
            .stdout
            .get_read_lock()
            .clone()
    }
}

use crate::runner::ws_log::LogWs;
/// get log
#[get("/log")]
async fn log_post(
    data: web::Data<AppState>,
    req: HttpRequest,
    stream: web::Payload,
) -> Result<impl Responder> {
    // loop {
    //     thread::sleep(Duration::from_secs(1));

    //     let a = data.get_wasm_log(0);
    //     print!("{}", String::from_utf8(a.get_ref().to_vec()).unwrap());
    //     // drop(a)
    // }

    ws::start(
        LogWs {
            data: data.server.lock().unwrap().clone(),
            hb: Instant::now(),
        },
        &req,
        stream,
    );
    Ok(web::Json(b""))
}
