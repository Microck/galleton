use std::collections::HashMap;
use galleton::Galleton;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::var("GALLETON_DIR").unwrap_or_else(|_| "./state".into());
    let client = Galleton::from_dir("http://127.0.0.1:8766", dir)?;
    let response = client.request("demo", "GET", "http://127.0.0.1:9909/me", &HashMap::new(), &[])?;
    println!("{} {}", response.status, String::from_utf8_lossy(&response.body));
    Ok(())
}
