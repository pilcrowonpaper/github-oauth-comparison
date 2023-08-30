use std::collections::HashMap;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{LOCATION, SET_COOKIE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rand::distributions::Alphanumeric;
use tokio::net::TcpListener;

use rand::Rng;
use serde::{Deserialize, Serialize};

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    read_dot_env();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;
    println!("Started server on port 3000");
    // We start a loop to continuously accept incoming connections
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(io, hyper::service::service_fn(handle_request))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_request(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/") => Ok(Response::new(Full::new(Bytes::from(
            "/login/github to login with Github!",
        )))),
        (&Method::GET, "/login/github") => handle_authorization().await,
        (&Method::GET, "/login/github/callback") => handle_callback(request).await,

        // Return 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::new(Full::new(Bytes::new()));
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

fn generate_random_string(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

async fn handle_authorization() -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    let state = generate_random_string(41);
    let mut authorization_url_query = SearchParams::new();
    authorization_url_query.insert("state", state.as_str());
    authorization_url_query.insert(
        "client_id",
        get_env_var_or_panic("GITHUB_CLIENT_ID").as_str(),
    );
    authorization_url_query.insert("response_type", "code");
    let authorization_url = format!(
        "https://github.com/login/oauth/authorize?{}",
        authorization_url_query.encode()
    );
    let state_cookie = format!("state={state}; Path=/; Max-Age=3600; HttpOnly");
    return Response::builder()
        .status(302)
        .header(SET_COOKIE, state_cookie)
        .header(LOCATION, authorization_url)
        .body(Full::new(Bytes::new()));
}

async fn handle_callback(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    let mut query = parse_query(request.uri().query().unwrap_or_default());
    let state = query.get("state").unwrap_or_default();
    let cookie = parse_cookie(
        request
            .headers()
            .get("Cookie")
            .map_or("", |header_value| header_value.to_str().unwrap_or_default()),
    );
    let state_cookie = cookie.get("state").map_or("", |v| v.as_str());
    if state != state_cookie {
        return Response::builder()
            .status(403)
            .body(Full::new(Bytes::new()));
    }
    let code = query.get("code").unwrap_or_default();
    let access_token = match exchange_authorization_code(code).await {
        Ok(v) => v,
        Err(_) => {
            return Response::builder()
                .status(422)
                .body(Full::new(Bytes::new()));
        }
    };
    let user = get_github_user(access_token.as_str()).await.unwrap();
    return Response::builder()
        .status(200)
        .body(Full::new(Bytes::from(format!(
            "User ID: {}\nUsername: {}",
            user.id, user.login
        ))));
}

#[derive(Serialize, Deserialize)]
struct AccessTokenResult {
    access_token: String,
}

async fn exchange_authorization_code(code: &str) -> Result<String, reqwest::Error> {
    let client = reqwest::Client::new();
    let result = match client
        .post("https://github.com/login/oauth/access_token")
        .form(&[
            (
                "client_id",
                get_env_var_or_panic("GITHUB_CLIENT_ID").as_str(),
            ),
            (
                "client_secret",
                get_env_var_or_panic("GITHUB_CLIENT_SECRET").as_str(),
            ),
            ("grant_type", "code"),
            ("code", code),
        ])
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(response) => response.json::<AccessTokenResult>().await?,
        Err(err) => return Err(err),
    };
    Ok(result.access_token)
}

#[derive(Serialize, Deserialize)]
struct GithubUser {
    id: i32,
    login: String,
}

async fn get_github_user(access_token: &str) -> Result<GithubUser, reqwest::Error> {
    let client = reqwest::Client::new();
    let user = match client
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .header("User-Agent", "rust")
        .send()
        .await
    {
        Ok(response) => response.json::<GithubUser>().await?,
        Err(err) => return Err(err),
    };
    Ok(user)
}

fn parse_cookie(cookie: &str) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for cookie_item in cookie.split(";") {
        match cookie_item.split_once("=") {
            Some((key, value)) => {
                map.insert(key.to_owned(), value.to_owned());
            }
            None => continue,
        }
    }
    map
}

fn parse_query(query: &str) -> SearchParams {
    let mut search_params = SearchParams::new();
    for query_item in query.split("&") {
        match query_item.split_once("=") {
            Some((key, value)) => {
                search_params.insert(key, value);
            }
            None => continue,
        }
    }
    search_params
}

struct SearchParams {
    values: HashMap<String, String>,
}

impl SearchParams {
    fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }
    fn insert(&mut self, key: &str, value: &str) {
        self.values.insert(key.to_owned(), value.to_owned());
    }
    fn get(&mut self, key: &str) -> Option<&str> {
        self.values.get(key).map(|v| v.as_str())
    }
    fn encode(&self) -> String {
        self.values
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&")
    }
}

fn read_dot_env() {
    let dot_env = std::fs::read_to_string("../.env").expect(".env not found");
    for item in dot_env.lines() {
        if let Some((key, value)) = item.split_once("=") {
            if value.starts_with("\"") && value.ends_with("\"") {
                std::env::set_var(key, &value[1..(value.chars().count() - 1)]);
            } else {
                std::env::set_var(key, value);
            }
        }
    }
}

fn get_env_var_or_panic(var_name: &str) -> String {
    std::env::var(var_name).expect(format!("Missing env var {}", var_name).as_str())
}
