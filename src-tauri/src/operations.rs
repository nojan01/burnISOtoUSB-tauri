//! One owner for disk activity and application replacement. Child processes must
//! be reaped before dropping the guard, so events cannot cross operation IDs.
use std::sync::{atomic::{AtomicU64, Ordering}, Mutex};

static NEXT: AtomicU64 = AtomicU64::new(0);
static ACTIVE: Mutex<Option<(u64, String)>> = Mutex::new(None);

pub struct Guard { pub id: u64 }
pub fn begin(resource: &str) -> Result<Guard, String> {
    let mut state = ACTIVE.lock().map_err(|_| "Operation state unavailable")?;
    if let Some((_, name)) = &*state {
        return Err(format!("Ein Vorgang läuft bereits ({name}). Bitte dessen Abschluss abwarten."));
    }
    let id = NEXT.fetch_add(1, Ordering::SeqCst) + 1;
    *state = Some((id, resource.to_owned()));
    Ok(Guard { id })
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut state) = ACTIVE.lock() {
            if state.as_ref().is_some_and(|(id, _)| *id == self.id) { *state = None; }
        }
    }
}
pub fn current_id() -> u64 {
    ACTIVE.lock().ok().and_then(|s| s.as_ref().map(|(id, _)| *id)).unwrap_or(0)
}
// Reservation persists across the frontend's download and install calls.
static UPDATE: Mutex<Option<Guard>> = Mutex::new(None);
#[tauri::command]
pub fn reserve_update() -> Result<(), String> {
    let guard = begin("Update")?;
    *UPDATE.lock().map_err(|_| "Update state unavailable")? = Some(guard);
    Ok(())
}
#[tauri::command]
pub fn release_update() { if let Ok(mut s) = UPDATE.lock() { s.take(); } }
pub fn can_restart() -> bool {
    ACTIVE.lock().is_ok_and(|s| s.as_ref().is_none_or(|(_, name)| name == "Update"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservation_prevents_overlap_and_keeps_id() {
        let first = begin("test-disk").unwrap();
        assert!(begin("other-disk").is_err());
        assert!(reserve_update().is_err());
        assert!(!can_restart());
        assert_eq!(current_id(), first.id);
        let id = first.id;
        drop(first);
        reserve_update().unwrap();
        assert!(can_restart());
        assert!(current_id() > id);
        assert!(begin("test-disk").is_err());
        release_update();
        assert_eq!(current_id(), 0);
    }
}
