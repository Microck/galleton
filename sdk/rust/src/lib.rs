//! Blocking, loopback-only Galleton client. In async applications call from a
//! blocking task/thread. The daemon owns refresh credentials and cookie rotation.
use std::{collections::HashMap, fmt, io::Read, net::IpAddr, path::Path, time::Duration};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{blocking::Client, redirect::Policy, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub retry_at: Option<String>,
}
#[derive(Debug)]
pub enum Error {
    InvalidInput(&'static str),
    Unavailable,
    InvalidResponse,
    Api(u16, ApiError),
    Io(std::io::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(s) => write!(f, "{s}"),
            Self::Unavailable => write!(f, "Galleton is unavailable or the local request timed out"),
            Self::InvalidResponse => write!(f, "Invalid Galleton response"),
            Self::Api(status, e) => write!(f, "Galleton HTTP {status}: {}: {}", e.code, e.message),
            Self::Io(_) => write!(f, "Could not read Galleton's local API token file"),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Default, Serialize)]
pub struct Credentials {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_cookies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<HashMap<String, String>>,
    pub replace: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct SessionStatus {
    pub id: String,
    pub provider: String,
    pub status: String,
    pub revision: u64,
    pub cookie_count: usize,
    pub created_at: String,
    pub last_refresh: Option<String>,
    pub next_refresh: Option<String>,
    pub access_expires_at: Option<String>,
    pub error: Option<ApiError>,
}
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Vec<u8>,
    pub revision: u64,
}
impl Response {
    pub fn is_success(&self) -> bool { (200..300).contains(&self.status) }
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_slice(&self.body).map_err(|_| Error::InvalidResponse)
    }
}
pub struct Galleton {
    base: String,
    token: String,
    client: Client,
}
fn path(id: &str) -> Result<String, Error> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err(Error::InvalidInput("Invalid session ID"));
    }
    Ok(format!("/v1/sessions/{id}"))
}
impl Galleton {
    pub fn new(base_url: &str, token: &str) -> Result<Self, Error> {
        let url = Url::parse(base_url).map_err(|_| Error::InvalidInput("Invalid daemon URL"))?;
        let host = url.host_str().unwrap_or("").trim_matches(|c| c == '[' || c == ']');
        let ip: IpAddr = host.parse().map_err(|_| Error::InvalidInput("Use a literal loopback address"))?;
        if !ip.is_loopback() || url.scheme() != "http" || !url.username().is_empty()
            || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
            return Err(Error::InvalidInput("Galleton requires a literal loopback HTTP origin"));
        }
        let token = token.trim();
        if token.is_empty() || token.contains('\r') || token.contains('\n') {
            return Err(Error::InvalidInput("Invalid local API token"));
        }
        let client = Client::builder().timeout(Duration::from_secs(300))
            .redirect(Policy::none()).no_proxy().build().map_err(|_| Error::Unavailable)?;
        Ok(Self { base: url.as_str().trim_end_matches('/').into(), token: token.into(), client })
    }
    pub fn from_dir(base_url: &str, directory: impl AsRef<Path>) -> Result<Self, Error> {
        let token = std::fs::read_to_string(directory.as_ref().join("api.token")).map_err(Error::Io)?;
        Self::new(base_url, &token)
    }
    fn call<T: serde::de::DeserializeOwned>(&self, method: Method, path: &str, body: Option<Value>) -> Result<T, Error> {
        let mut req = self.client.request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token).header("Content-Type", "application/json");
        if let Some(value) = body { req = req.json(&value); }
        let response = req.send().map_err(|_| Error::Unavailable)?;
        let status = response.status().as_u16();
        let mut raw = Vec::new();
        response.take(8 * 1024 * 1024 + 1).read_to_end(&mut raw).map_err(|_| Error::Api(status, ApiError {
            code: "daemon_unavailable".into(),
            message: "Galleton response was interrupted; the request may already have completed.".into(),
            retry_at: None,
        }))?;
        if raw.len() > 8 * 1024 * 1024 { return Err(Error::InvalidResponse); }
        if !(200..300).contains(&status) {
            #[derive(Deserialize)] struct Envelope { error: ApiError }
            let error = serde_json::from_slice::<Envelope>(&raw).map(|e| e.error).unwrap_or_else(|_| ApiError {
                code: "daemon_error".into(), message: "Galleton request failed.".into(), retry_at: None,
            });
            return Err(Error::Api(status, error));
        }
        serde_json::from_slice(&raw).map_err(|_| Error::InvalidResponse)
    }
    pub fn connect(&self, id: &str, credentials: &Credentials) -> Result<SessionStatus, Error> {
        self.call(Method::PUT, &path(id)?, Some(serde_json::to_value(credentials).map_err(|_| Error::InvalidResponse)?))
    }
    pub fn status(&self, id: &str) -> Result<SessionStatus, Error> { self.call(Method::GET, &path(id)?, None) }
    pub fn list(&self) -> Result<Vec<SessionStatus>, Error> {
        #[derive(Deserialize)] struct List { sessions: Vec<SessionStatus> }
        let list: List = self.call(Method::GET, "/v1/sessions", None)?;
        Ok(list.sessions)
    }
    pub fn refresh(&self, id: &str) -> Result<SessionStatus, Error> {
        self.call(Method::POST, &format!("{}/refresh", path(id)?), Some(json!({})))
    }
    pub fn headers(&self, id: &str, url: &str) -> Result<HashMap<String, String>, Error> {
        #[derive(Deserialize)] struct Headers { headers: HashMap<String, String> }
        let result: Headers = self.call(Method::POST, &format!("{}/headers", path(id)?), Some(json!({"url": url})))?;
        Ok(result.headers)
    }
    pub fn capture(&self, id: &str, url: &str, set_cookie: &[String]) -> Result<SessionStatus, Error> {
        self.call(Method::POST, &format!("{}/cookies", path(id)?), Some(json!({"url": url, "set_cookie": set_cookie})))
    }
    pub fn forget(&self, id: &str) -> Result<(), Error> {
        let _: Value = self.call(Method::DELETE, &path(id)?, None)?; Ok(())
    }
    pub fn request(&self, id: &str, method: &str, url: &str,
                   headers: &HashMap<String, String>, body: &[u8]) -> Result<Response, Error> {
        if body.len() > 1024 * 1024 { return Err(Error::InvalidInput("Request body exceeds 1 MiB")); }
        #[derive(Deserialize)] struct Wire {
            status: u16, headers: HashMap<String, Vec<String>>, body_base64: String, revision: u64,
        }
        let wire: Wire = self.call(Method::POST, &format!("{}/request", path(id)?), Some(json!({
            "url": url, "method": method, "headers": headers, "body_base64": STANDARD.encode(body)
        })))?;
        Ok(Response { status: wire.status, headers: wire.headers,
            body: STANDARD.decode(wire.body_base64).map_err(|_| Error::InvalidResponse)?, revision: wire.revision })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn rejects_remote_daemon() { assert!(Galleton::new("http://example.com", "local").is_err()); }
    #[test] fn rejects_invalid_id() { assert!(path("../other").is_err()); }
    #[test] fn accepts_loopback() { assert!(Galleton::new("http://127.0.0.1:8766", "local").is_ok()); }
    #[test] fn rejects_header_injection() { assert!(Galleton::new("http://127.0.0.1:8766", "a\r\nb").is_err()); }
    #[test]
    fn malformed_error_bodies_preserve_status() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        for body in ["", "not json", "{", "{}"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                socket.read(&mut request).unwrap();
                write!(socket, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            });
            let client = Galleton::new(&format!("http://{address}"), "local").unwrap();
            match client.status("account") {
                Err(Error::Api(status, error)) => { assert_eq!(status, 503); assert_eq!(error.code, "daemon_error"); }
                _ => panic!("HTTP status lost"),
            }
            server.join().unwrap();
        }
    }
    #[test]
    fn interrupted_response_body_preserves_ambiguous_status() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            socket.read(&mut request).unwrap();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{{}}").unwrap();
        });
        let client = Galleton::new(&format!("http://{address}"), "local").unwrap();
        match client.status("account") {
            Err(Error::Api(status, error)) => {
                assert_eq!(status, 200);
                assert_eq!(error.code, "daemon_unavailable");
                assert!(error.message.contains("may already have completed"));
            }
            other => panic!("interrupted response lost ambiguity: {other:?}"),
        }
        server.join().unwrap();
    }
}
