//! Invoke bundled F3 as separate executables; do not link GPL code into the app.
use super::*;

fn binary(name: &str) -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let bundled = executable.parent().ok_or("App-Verzeichnis fehlt")?.join(name);
    if bundled.is_file() { return Ok(bundled); }
    #[cfg(debug_assertions)]
    {
        let target = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" };
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(format!("binaries/{name}-{target}-apple-darwin"));
        if dev.is_file() { return Ok(dev); }
    }
    Err(format!("Mitgeliefertes {name} fehlt. Bitte die App neu installieren."))
}

#[tauri::command]
pub async fn list_f3_volumes(disk_id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        ensure_writable_target(&disk_id)?;
        let python = get_python3_path().ok_or("Python 3 fehlt zur Volume-Prüfung")?;
        let cfg = serde_json::json!({"action":"list", "disk_id":disk_id});
        let out = Command::new(python).args(["-I", "-c", include_str!("f3_worker.py"), &cfg.to_string()])
            .current_dir("/").output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).trim().into()); }
        serde_json::from_slice(&out.stdout).map_err(|e| format!("Ungültige Volume-Liste: {e}"))
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn diagnose_f3(app: AppHandle, disk_id: String, volume_id: String, volume_uuid: String) -> Result<DiagnoseResult, String> {
    let guard = start_operation(&disk_id)?;
    CANCEL_DIAGNOSE.store(false, Ordering::SeqCst);
    app.emit("operation_start", guard.id).ok();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        ensure_writable_target(&disk_id)?;
        let cfg = serde_json::json!({"disk_id":disk_id,"volume_id":volume_id,"volume_uuid":volume_uuid,
                                    "f3write":binary("f3write")?,"f3read":binary("f3read")?});
        let mut result = None;
        let mut protocol_error = None;
        process_runner::run_f3(&cfg, &CANCEL_DIAGNOSE, |line| {
            let Some((kind, json)) = line.split_once(':') else { return; };
            if !matches!(kind, "DSTAT" | "DRESULT") { return; }
            let data: serde_json::Value = match serde_json::from_str(json) {
                Ok(d) => d,
                Err(e) => { protocol_error = Some(e.to_string()); return; }
            };
            if kind == "DRESULT" { result = Some(data); return; }
            let phase = data["phase"].as_str().unwrap_or("read");
            app.emit("diagnose_progress", DiagnoseProgressEvent {
                percent:data["percent"].as_u64().unwrap_or(0).min(99) as u32,
                status:String::new(), phase:phase.into(),
                sectors_checked:0, // F3 progress is an estimate; exact counts arrive in the report.
                errors_found:0,
                read_speed_mbps:data["read_mib_s"].as_f64().unwrap_or(0.0),
                write_speed_mbps:data["write_mib_s"].as_f64().unwrap_or(0.0),
                operation_id:operations::current_id(), details:Some(data),
            }).ok();
        })?;
        if let Some(e) = protocol_error { return Err(e); }
        let data = result.ok_or("F3-Ergebnis fehlt")?;
        if data["complete"] != true || !data["success"].is_boolean() || !data["bytes_checked"].is_u64() {
            return Err("Unvollständiges F3-Ergebnis".into());
        }
        Ok(DiagnoseResult {
            success:data["success"] == true,
            total_sectors:data["bytes_checked"].as_u64().unwrap_or(0)/512,
            sectors_checked:data["bytes_checked"].as_u64().unwrap_or(0)/512,
            errors_found:data["errors_found"].as_u64().unwrap_or(0), bad_sectors:Vec::new(),
            read_speed_mbps:data["read_mib_s"].as_f64().unwrap_or(0.0),
            write_speed_mbps:data["write_mib_s"].as_f64().unwrap_or(0.0),
            message:"F3-Dateiprüfung abgeschlossen; nur die geschriebenen Testdateien wurden geprüft.".into(),
            details:Some(data),
        })
    }).await.map_err(|e| e.to_string())?
}
