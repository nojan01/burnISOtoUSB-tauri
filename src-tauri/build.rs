fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target.ends_with("apple-darwin") {
        for path in ["../vendor", "../scripts/build-f3.sh", "../scripts/f3-argp-config.h"] {
            println!("cargo:rerun-if-changed={path}");
        }
        assert!(std::process::Command::new("bash")
            .args(["../scripts/build-f3.sh", &target]).status().unwrap().success(),
            "Building bundled F3 failed");
    }
    tauri_build::build()
}
