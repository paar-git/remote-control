//! Desktop client executable.
//!
//! A thin launcher: everything lives in the `rc_desktop_client_lib` library so that
//! the backend can be unit-tested without starting a webview.

// Suppress the extra console window on Windows release builds. The client is a GUI
// application; in debug builds the console is kept so logs stay visible.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if std::env::args().any(|arg| arg == "--update-health-check") {
        let args: Vec<String> = std::env::args().collect();
        let transaction_id = value_after(&args, "--update-transaction-id").unwrap_or_default();
        let expected_version = value_after(&args, "--update-expected-version").unwrap_or_default();
        if transaction_id.is_empty() || expected_version != env!("CARGO_PKG_VERSION") {
            eprintln!("UPDATE_BOOT_REJECTED");
            std::process::exit(2);
        }
        println!(
            "UPDATE_BOOT_OK {{\"transactionId\":\"{}\",\"version\":\"{}\",\"status\":\"healthy\"}}",
            escape_json(&transaction_id),
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    rc_desktop_client_lib::run();
}

fn value_after(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].clone())
}

fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
