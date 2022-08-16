use actix_web::{get, App, HttpRequest, HttpResponse, HttpServer, Responder};
use once_cell::sync::OnceCell;
use rand::distributions::{Alphanumeric, DistString};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::env;
use std::process;
use std::{fs::File, io::BufReader};

static SECRET: OnceCell<String> = OnceCell::new();

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "You need to specify a command to be executed\nusage: {} <command><arguments>",
            args[0]
        );
        process::exit(1);
    }
    // load TLS key/cert files
    let cert_path = env::var("CMD_HOOK_CERT").unwrap_or_else(|_| {
        println!(
            "Using cert at:    ./cert.pem,                        set CMD_HOOK_CERT to change"
        );
        "cert.pem".to_string()
    });
    let cert_file = &mut BufReader::new(File::open(cert_path).expect("Could not open cert file"));
    let key_path = env::var("CMD_HOOK_KEY").unwrap_or_else(|_| {
        println!("Using key at:     ./key.pem,                         set CMD_HOOK_KEY to change");
        "key.pem".to_string()
    });
    let key_file = &mut BufReader::new(File::open(key_path).expect("Could not open key file"));

    let secret = env::var("CMD_HOOK_SECRET").unwrap_or_else(|_| {
        let rng = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        println!("Using auth secret: {}, set CMD_HOOK_SECRET to change", rng);
        rng
    });
    SECRET.set(secret).unwrap();
    let host = env::var("CMD_HOOK_HOST").unwrap_or_else(|_| {
        println!(
            "Using host:        localhost,                        set CMD_HOOK_HOST to change"
        );
        "0.0.0.0".to_string()
    });
    let port = env::var("CMD_HOOK_PORT").unwrap_or_else(|_| {
        println!(
            "Using port:        8080,                             set CMD_HOOK_PORT to change"
        );
        "8080".to_string()
    });
    let port = port.parse::<u16>().expect("Could not parse port");

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();
    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();
    // exit if no keys could be parsed
    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }
    let config = config.with_single_cert(cert_chain, keys.remove(0)).unwrap();
    HttpServer::new(|| App::new().service(execute))
        .bind_rustls(format!("{}:{}", host, port), config)?
        .run()
        .await
}

#[get("/")]
async fn execute(req: HttpRequest) -> impl Responder {
    let secret = SECRET.wait();
    if let Some(auth) = req.headers().get("Authorization") {
        if auth != secret {
            return HttpResponse::Found().body("Forbidden");
        }
    } else {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }

    let args: Vec<String> = env::args().collect();
    match process::Command::new(&args[1]).args(&args[2..]).output() {
        Ok(output) => HttpResponse::Ok().body(output.stdout),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
