//! A privileged supervisor owns the worker's process group. Cancellation travels
//! over stdin; the unprivileged UI never has to kill a root process itself.
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{atomic::{AtomicBool, Ordering}, mpsc};
use std::time::Duration;

pub fn run(config: &serde_json::Value, password: Option<&str>, cancel: &AtomicBool,
           event: impl FnMut(&str)) -> Result<(), String> {
    run_with_sudo(config, password, cancel, event, std::path::Path::new("/usr/bin/sudo"))
}

fn run_with_sudo(config: &serde_json::Value, password: Option<&str>, cancel: &AtomicBool,
                 event: impl FnMut(&str), sudo: &std::path::Path) -> Result<(), String> {
    let script = format!("{}\n{}", include_str!("worker.py"), include_str!("supervisor.py"));
    run_script(config, password, cancel, event, sudo, &script)
}

pub fn run_f3(config: &serde_json::Value, cancel: &AtomicBool,
              event: impl FnMut(&str)) -> Result<(), String> {
    run_script(config, None, cancel, event, std::path::Path::new("/usr/bin/sudo"),
               include_str!("f3_worker.py"))
}

fn run_script(config: &serde_json::Value, password: Option<&str>, cancel: &AtomicBool,
              mut event: impl FnMut(&str), sudo: &std::path::Path, script: &str) -> Result<(), String> {
    if cancel.load(Ordering::SeqCst) { return Err("Vorgang vor dem Start abgebrochen.".into()); }
    let python = super::get_python3_path().ok_or("Python 3 fehlt (brew install python)")?;
    if let Some(pw) = password {
        // -k MUST be a separate call. Combined with -v it validates the password
        // but deliberately does not update the ticket needed by the -n launch.
        let reset = Command::new(sudo).arg("-k")
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped())
            .output().map_err(|e| e.to_string())?;
        if !reset.status.success() {
            return Err("Administrator-Prüfung konnte nicht vorbereitet werden.".into());
        }
        if cancel.load(Ordering::SeqCst) { return Err("Vorgang vor dem Start abgebrochen.".into()); }
        // Authenticate on a separate, closed pipe. Keeping sudo's password pipe
        // open for cancellation would hang after a wrong password/re-prompt.
        let mut auth = Command::new(sudo).args(["-S", "-p", "", "-v"])
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped())
            .spawn().map_err(|e| e.to_string())?;
        if let Some(mut input) = auth.stdin.take() { let _ = writeln!(input, "{pw}"); }
        let result = auth.wait_with_output().map_err(|e| e.to_string())?;
        if !result.status.success() { return Err("Administrator-Prüfung fehlgeschlagen: Passwort falsch oder sudo nicht erlaubt.".into()); }
        if cancel.load(Ordering::SeqCst) { return Err("Vorgang vor dem Start abgebrochen.".into()); }
    }
    if let Some(disk) = config.get("device").and_then(|v| v.as_str()).and_then(|s| s.strip_prefix("/dev/r")) {
        if !super::is_valid_disk_id(disk) { return Err("Ungültige Raw-Gerätekennung".into()); }
        // Authentication may have taken time; reject a volume remounted meanwhile.
        super::verify_disk_unmounted(disk)?;
    }
    let mut command = if password.is_some() {
        let mut c = Command::new(sudo);
        c.args(["-n", "--", &python]); c
    } else { Command::new(python) };
    // Do not inherit a protected Documents cwd or import Python modules from it.
    // All operation paths are absolute; isolated mode also ignores PYTHONPATH.
    let mut child = command.args(["-I", "-u", "-c", &script, &config.to_string()])
        .current_dir("/")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|e| format!("Prozessstart: {e}"))?;
    let mut input = child.stdin.take().ok_or("Kein Steuerkanal")?;
    let stdout = child.stdout.take().ok_or("Kein stdout")?;
    let mut stderr = child.stderr.take().ok_or("Kein stderr")?;
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line).is_err() { break; }
        }
    });
    let errors = std::thread::spawn(move || {
        // Drain continuously (no pipe deadlock), retaining only the error tail.
        let mut tail = std::collections::VecDeque::with_capacity(65536);
        let mut buffer = [0u8; 4096];
        while let Ok(size) = stderr.read(&mut buffer) {
            if size == 0 { break; }
            tail.extend(&buffer[..size]);
            if tail.len() > 65536 { tail.drain(..tail.len() - 65536); }
        }
        String::from_utf8_lossy(&tail.into_iter().collect::<Vec<_>>()).into_owned()
    });
    let mut cancelled = false;
    let mut complete = false;
    let mut stream_error = None;
    loop {
        if !cancelled && cancel.load(Ordering::SeqCst) {
            // Do not report completion until the supervisor confirms worker exit.
            let _ = writeln!(input, "CANCEL");
            cancelled = true;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(line)) => {
                if line == "DONE" { complete = true; }
                if !cancelled { event(&line); }
            }
            Ok(Err(e)) => { stream_error = Some(e.to_string()); }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    let _ = reader.join();
    let error = errors.join().unwrap_or_default();
    if cancelled { return Err(format!("Vorgang abgebrochen; Schreibprozess beendet. {}", error.trim())); }
    if !status.success() || !complete || stream_error.is_some() {
        return Err(format!("Vorgang fehlgeschlagen: {}", if error.trim().is_empty() {
            stream_error.unwrap_or_else(|| status.to_string())
        } else { error.trim().to_string() }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // No actual sudo, password or privilege escalation in these tests. The shim
    // models documented -k/-v semantics, then execs the real unprivileged worker.
    fn sudo_fixture(root: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("sudo-fixture");
        let python = super::super::get_python3_path().unwrap();
        let source = r#"
import os, sys
from pathlib import Path
root = Path(__file__).parent
ticket = root / 'ticket'
args = sys.argv[1:]
with (root / 'calls').open('a') as log:
    log.write(('reset' if args == ['-k'] else 'validate' if '-v' in args else 'launch') + '\n')
if args == ['-k']:
    if ticket.exists(): ticket.unlink()
    sys.exit(0)
if '-v' in args:
    # read() must get EOF, including after an invalid password/re-prompt.
    if sys.stdin.read() != 'fixture-password\n': sys.exit(1)
    if '-k' not in args: ticket.touch()
    sys.exit(0)
assert args[:2] == ['-n', '--']
if not ticket.exists():
    print('sudo: a password is required', file=sys.stderr)
    sys.exit(1)
os.execv(args[2], args[2:])
"#;
        std::fs::write(&path, format!("#!{python}\n{source}")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn sudo_validation_creates_ticket_before_noninteractive_worker_launch() {
        let temp = tempfile::tempdir().unwrap();
        let sudo = sudo_fixture(temp.path());
        let cfg = serde_json::json!({"mode":"command","script":"true"});
        run_with_sudo(&cfg, Some("fixture-password"), &AtomicBool::new(false), |_| {}, &sudo).unwrap();
        assert_eq!(std::fs::read_to_string(temp.path().join("calls")).unwrap(), "reset\nvalidate\nlaunch\n");
    }

    #[test]
    fn sudo_wrong_password_closes_input_and_never_launches_worker() {
        let temp = tempfile::tempdir().unwrap();
        let sudo = sudo_fixture(temp.path());
        let started = std::time::Instant::now();
        let cfg = serde_json::json!({"mode":"command","script":"true"});
        let error = run_with_sudo(&cfg, Some("incorrect-fixture-password"), &AtomicBool::new(false), |_| {}, &sudo).unwrap_err();
        assert!(error.contains("Passwort falsch"));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(std::fs::read_to_string(temp.path().join("calls")).unwrap(), "reset\nvalidate\n");
    }

    #[test]
    fn sudo_cancelled_before_start_does_not_authenticate() {
        let temp = tempfile::tempdir().unwrap();
        let sudo = sudo_fixture(temp.path());
        let cfg = serde_json::json!({"mode":"command","script":"true"});
        assert!(run_with_sudo(&cfg, Some("fixture-password"), &AtomicBool::new(true), |_| {}, &sudo).is_err());
        assert!(!temp.path().join("calls").exists());
    }

    #[test]
    fn runner_publishes_only_a_complete_backup() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("backup.img");
        std::fs::write(&source, b"complete bytes").unwrap();
        let cfg = serde_json::json!({"mode":"backup","device":source,"destination":output,"size":14});
        run(&cfg, None, &AtomicBool::new(false), |_| {}).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"complete bytes");
        assert!(run(&cfg, None, &AtomicBool::new(false), |_| {}).is_err());
    }

    #[test]
    fn runner_cancels_silent_child_and_waits_for_exit() {
        let cancelled = std::sync::Arc::new(AtomicBool::new(false));
        let control = cancelled.clone();
        let trigger = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            control.store(true, Ordering::SeqCst);
        });
        let started = std::time::Instant::now();
        let result = run(&serde_json::json!({"mode":"command","script":"sleep 30"}), None, &cancelled, |_| {});
        trigger.join().unwrap();
        assert!(result.unwrap_err().contains("abgebrochen"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn runner_rejects_nonzero_exit_even_if_stdout_claims_done() {
        let cfg = serde_json::json!({"mode":"command","script":"echo DONE; exit 7"});
        assert!(run(&cfg, None, &AtomicBool::new(false), |_| {}).is_err());
    }
}
