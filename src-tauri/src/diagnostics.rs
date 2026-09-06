//! Structured progress/results for read-only scans and speed measurements.
use super::*;

fn number(value: &serde_json::Value, key: &str) -> f64 {
    value[key].as_f64().filter(|v| v.is_finite() && *v >= 0.0).unwrap_or(0.0)
}

fn result_from(details: serde_json::Value, size: u64) -> Result<DiagnoseResult, String> {
    if details["complete"] != true || !details["bytes_checked"].is_u64() || !details["success"].is_boolean() {
        return Err("Diagnose hat kein vollständiges Ergebnis geliefert".into());
    }
    let success = details["success"] == true;
    let message = match details["kind"].as_str() {
        Some("speed") => "Geschwindigkeitstest abgeschlossen; gewichteter Gesamtdurchsatz und Einzelmessungen verfügbar.",
        Some("sample") if success => "Stichprobe ohne Lesefehler beendet. Dies ist kein vollständiger Surface Scan.",
        Some("surface") if success => "Vollständiger Surface Scan ohne bleibende Lesefehler beendet.",
        Some("sample" | "surface") => "Scan beendet: Nicht lesbare Bereiche gefunden. Details beachten.",
        _ => return Err("Unbekanntes Diagnose-Ergebnis".into()),
    };
    Ok(DiagnoseResult {
        success, total_sectors:size/512,
        sectors_checked:details["readable_bytes"].as_u64().or_else(|| details["bytes_checked"].as_u64()).unwrap_or(0)/512,
        errors_found:details["errors_found"].as_u64().unwrap_or(0),
        bad_sectors:Vec::new(), // Regions are not exact defective sectors.
        read_speed_mbps:number(&details, "read_mib_s"),
        write_speed_mbps:number(&details, "write_mib_s"),
        message:message.into(), details:Some(details),
    })
}

pub async fn run(app: AppHandle, disk_id: String, password: String, mode: &str, profile: &str) -> Result<DiagnoseResult, String> {
    if !matches!(mode, "surface" | "sample" | "speed") || !matches!(profile, "quick" | "detailed") {
        return Err("Ungültiger Diagnosemodus".into());
    }
    let mode = mode.to_string();
    let profile = profile.to_string();
    let guard = start_operation(&disk_id)?;
    CANCEL_DIAGNOSE.store(false, Ordering::SeqCst);
    app.emit("operation_start", guard.id).ok();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        if !is_valid_disk_id(&disk_id) { return Err("Invalid disk identifier".into()); }
        if mode == "speed" { ensure_writable_target(&disk_id)?; }
        let size = get_disk_size(&disk_id)?;
        ensure_disk_unmounted(&app, &disk_id)?;
        let cfg = serde_json::json!({"mode":mode,"speed_profile":profile,"seconds":30,
            "device":format!("/dev/r{disk_id}"),"size":size});
        let mut result = None;
        let mut protocol_error = None;
        let execution = process_runner::run(&cfg, Some(&password), &CANCEL_DIAGNOSE, |line| {
            let Some((event, json)) = line.split_once(':') else { return; };
            if !matches!(event, "DSTAT" | "DRESULT") { return; }
            let data: serde_json::Value = match serde_json::from_str(json) {
                Ok(value) => value,
                Err(e) => { protocol_error = Some(format!("Ungültige Diagnosemeldung: {e}")); return; }
            };
            if event == "DRESULT" { result = Some(data); return; }
            let phase = data["phase"].as_str().unwrap_or("reading").to_owned();
            let _ = app.emit("diagnose_progress", DiagnoseProgressEvent {
                percent:number(&data,"percent").min(99.0) as u32,
                status:String::new(), phase,
                sectors_checked:data["readable_bytes"].as_u64().or_else(|| data["bytes_checked"].as_u64()).unwrap_or(0)/512,
                errors_found:data["errors_found"].as_u64().unwrap_or(0),
                read_speed_mbps:number(&data,"read_mib_s"),
                write_speed_mbps:number(&data,"write_mib_s"),
                operation_id:operations::current_id(), details:Some(data),
            });
        });
        // Reaped worker first, then remount; also attempted on scan failure.
        let _ = Command::new("diskutil").args(["mountDisk", &disk_id]).output();
        execution?;
        if let Some(error) = protocol_error { return Err(error); }
        result_from(result.ok_or("Diagnose-Ergebnis fehlt")?, size)
    }).await.map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sample_and_failed_regions_keep_their_scope() {
        let sample = serde_json::json!({"kind":"sample","sampled":true,"complete":true,"success":true,"bytes_checked":512,"errors_found":0});
        let result = result_from(sample, 4096).unwrap();
        assert!(result.message.contains("kein vollständiger"));
        assert_eq!(result.sectors_checked, 1);
        let failed = serde_json::json!({"kind":"surface","complete":true,"success":false,"bytes_checked":4096,"readable_bytes":3584,"errors_found":1,
            "bad_ranges":[{"offset":512,"length":512}]});
        let result = result_from(failed,4096).unwrap();
        assert!(!result.success);
        assert_eq!(result.sectors_checked, 7);
        assert!(result.bad_sectors.is_empty());
        assert_eq!(result.details.unwrap()["bad_ranges"][0]["offset"],512);
        assert!(result_from(serde_json::json!({"success":true}),4096).is_err());
    }
}
