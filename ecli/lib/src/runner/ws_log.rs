use std::time::{Duration, Instant};

use actix::{Actor, ActorContext, AsyncContext, StreamHandler};
use actix_web_actors::ws;

use super::utils::ServerData;

/// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct LogWs {
    pub data: ServerData,
    pub hb: Instant,
}

impl Actor for LogWs {
    type Context = ws::WebsocketContext<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

impl LogWs {
    fn hb(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // heartbeat timed out
                println!("Websocket Client heartbeat failed, disconnecting!");

                // stop actor
                ctx.stop();

                // don't try to send a ping
                return;
            }

            ctx.ping(b"");
        });
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for LogWs {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        let msg = match msg {
            Err(_) => {
                ctx.stop();
                return;
            }
            Ok(msg) => msg,
        };

        log::debug!("WEBSOCKET MESSAGE: {msg:?}");

        match msg {
            ws::Message::Ping(msg) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            ws::Message::Pong(_) => {
                self.hb = Instant::now();
            }
            ws::Message::Text(text) => {
                let id: serde_json::Value = serde_json::from_str(text.trim()).unwrap();

                let prog_id = usize::try_from(id["id"].as_i64().unwrap()).unwrap();

                let prog_type = self.data.get_type_of(prog_id).unwrap();

                match prog_type {
                    crate::config::ProgramType::WasmModule => {
                        // let mut log = self.data.wasm_tasks.get(&prog_id).unwrap().log_msg.clone();

                        let b = self
                            .data
                            .wasm_tasks
                            .get(&prog_id)
                            .unwrap()
                            .log_msg
                            .stdout
                            .clone();
                        // #[allow(unused)]
                        // loop {
                        // }
                        // ctx.text("Test".to_string())
                        for u in b.into_iter() {
                            ctx.text(u.to_string())
                        }
                    }
                    _ => todo!(),
                }
            }
            ws::Message::Binary(_) => println!("Unexpected binary"),
            ws::Message::Close(reason) => {
                ctx.close(reason);
                ctx.stop();
            }
            ws::Message::Continuation(_) => {
                ctx.stop();
            }
            ws::Message::Nop => (),
        }
    }
}
