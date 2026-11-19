// SPDX-License-Identifier: MIT
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["--help"] || args == ["-h"] {
        print!("{}", enzimos_remote_access::client::HELP);
        return;
    }
    let result = enzimos_remote_access::client::parse(&args).and_then(|command| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| enzimos_platform::Error("remote-client-runtime-unavailable".into()))?;
        runtime.block_on(enzimos_remote_access::client::execute(command))
    });
    match result {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(text) => println!("{text}"),
            Err(_) => {
                eprintln!("Remote access refused: remote-reply-invalid");
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("Remote access refused: {error}");
            std::process::exit(1);
        }
    }
}
