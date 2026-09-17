// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Some(code) = burniso_usb_lib::forensic_helper_exit_code() {
        std::process::exit(code);
    }
    burniso_usb_lib::run()
}
