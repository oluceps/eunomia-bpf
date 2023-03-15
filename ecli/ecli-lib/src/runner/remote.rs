use crate::config::*;
use crate::error::{EcliError, EcliResult};
use crate::handle_json;
use crate::wasm_bpf_runner::wasm::handle_wasm;
use async_trait::async_trait;
use hyper::server::conn::Http;
use hyper::service::Service;
use log::info;
use openapi_client::server::MakeService;
use openapi_client::{Api, ListGetResponse, StartPostResponse, StopPostResponse};
use std::marker::PhantomData;
use swagger::auth::MakeAllowAllAuthenticator;
use swagger::ApiError;
pub use swagger::{AuthData, ContextBuilder, EmptyContext, Has, Push, XSpanIdString};
use tokio::net::TcpListener;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};

use openapi_client::models;

pub type ClientContext = swagger::make_context_ty!(
    ContextBuilder,
    EmptyContext,
    Option<AuthData>,
    XSpanIdString
);

/// Builds an SSL implementation for Simple HTTPS from some hard-coded file names
pub async fn create(addr: &str, https: bool) {
    let addr = addr.parse().expect("Failed to parse bind address");

    let server = Server::new();

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
            .await
            .unwrap()
    }
}

#[derive(Clone)]
pub struct Server<C> {
    // tasks: HashMap<usize, Worker>,
    marker: PhantomData<C>,
}

impl<C> Server<C> {
    pub fn new() -> Self {
        Server {
            // tasks: HashMap::new(),
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
        println!("Recieved List request");
        info!("list_get() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError("This server behavior not implemented".into()))
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
        info!(
            "start_post({:?}, {:?}, {:?}) - X-Span-ID: {:?}",
            program_data_buf,
            program_type,
            extra_params,
            context.get().0.clone()
        );

        let empty_extra_params = vec![String::default()];

        #[allow(unused)]
        let (program_data_buf, program_type, extra_params, btf_data) = (
            program_data_buf.unwrap().as_slice(),
            btf_data.unwrap().as_slice(),
            program_type.unwrap(),
            extra_params.unwrap_or_else(|| &empty_extra_params),
        );

        Err(ApiError("This server behavior not implemented".into()))
    }

    /// Stop a task by id or name
    async fn stop_post(
        &self,
        list_get200_response_tasks_inner: models::ListGet200ResponseTasksInner,
        context: &C,
    ) -> Result<StopPostResponse, ApiError> {
        let context = context.clone();
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

        Err(ApiError("This server behavior not implemented".into()))
    }
}
