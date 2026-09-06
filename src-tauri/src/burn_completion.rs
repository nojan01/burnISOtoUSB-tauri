//! Keep a proven write/verify result separate from optional mount/eject cleanup.
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct BurnResult {
    pub written: bool,
    pub verified: bool,
    pub warning: Option<CompletionWarning>,
}

#[derive(Debug, Serialize)]
pub struct CompletionWarning {
    pub action: &'static str,
    pub detail: String,
}

#[derive(Default)]
pub struct Evidence {
    written: bool,
    verified: bool,
}

impl Evidence {
    pub fn observe(&mut self, line: &str) {
        match line {
            "WRITE_SUCCESS" => self.written = true,
            "VERIFY_SUCCESS" => self.verified = true,
            _ => {}
        }
    }

    pub fn finish(
        self,
        worker: Result<(), String>,
        verify_requested: bool,
        eject: bool,
        finalize: impl FnOnce(&'static str) -> Result<(), String>,
    ) -> Result<BurnResult, String> {
        // Never downgrade an I/O error, mismatch, cancellation or incomplete
        // worker protocol to a successful operation with a cleanup warning.
        worker?;
        if !self.written || (verify_requested && !self.verified) {
            return Err("Schreib- oder Verifizierungsbestätigung fehlt".into());
        }
        // One action only. In particular, never fall back to eject after a
        // failed mount: ejection requires the user's explicit checkbox.
        let action = if eject { "eject" } else { "mountDisk" };
        let warning = finalize(action).err().map(|detail| CompletionWarning {
            action: if eject { "eject" } else { "mount" },
            detail,
        });
        Ok(BurnResult {
            written: true,
            verified: verify_requested && self.verified,
            warning,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified() -> Evidence {
        let mut evidence = Evidence::default();
        evidence.observe("WRITE_SUCCESS");
        evidence.observe("VERIFY_SUCCESS");
        evidence
    }

    #[test]
    fn missing_disk_or_unsupported_mount_preserves_verified_success() {
        for detail in [
            "Failed to find disk /dev/disk10",
            "No mountable file systems",
        ] {
            let result = verified()
                .finish(Ok(()), true, false, |action| {
                    assert_eq!(action, "mountDisk");
                    Err(detail.into())
                })
                .unwrap();
            assert!(result.written && result.verified);
            let warning = result.warning.unwrap();
            assert_eq!(warning.action, "mount");
            assert_eq!(warning.detail, detail);
        }
    }

    #[test]
    fn eject_failure_does_not_claim_unrequested_verification() {
        let mut evidence = Evidence::default();
        evidence.observe("WRITE_SUCCESS");
        let result = evidence
            .finish(Ok(()), false, true, |action| {
                assert_eq!(action, "eject");
                Err("Resource busy".into())
            })
            .unwrap();
        assert!(result.written && !result.verified);
        assert_eq!(result.warning.unwrap().action, "eject");
    }

    #[test]
    fn worker_errors_and_cancellation_remain_errors_without_finalization() {
        for error in [
            "I/O error",
            "Verifizierung: fehlerhafte Blöcke",
            "Vorgang abgebrochen",
        ] {
            let result =
                verified().finish(Err(error.into()), true, false, |_| panic!("must not mount"));
            assert_eq!(result.unwrap_err(), error);
        }
    }

    #[test]
    fn incomplete_write_or_verification_cannot_be_successful() {
        let mut written_only = Evidence::default();
        written_only.observe("WRITE_SUCCESS");
        for evidence in [Evidence::default(), written_only] {
            assert!(evidence
                .finish(Ok(()), true, false, |_| panic!("must not mount"))
                .is_err());
        }
    }

    #[test]
    fn successful_cleanup_has_no_warning_and_serializes_evidence() {
        let result = verified().finish(Ok(()), true, true, |_| Ok(())).unwrap();
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            serde_json::json!({
                "written":true, "verified":true, "warning":null
            })
        );
    }

    #[test]
    fn unchecked_eject_never_dispatches_ejection_even_after_mount_failure() {
        for failed in [false, true] {
            let mut actions = Vec::new();
            verified()
                .finish(Ok(()), true, false, |action| {
                    actions.push(action);
                    if failed {
                        Err("missing disk".into())
                    } else {
                        Ok(())
                    }
                })
                .unwrap();
            assert_eq!(actions, ["mountDisk"]);
        }
    }

    #[test]
    fn checked_eject_dispatches_exactly_one_ejection() {
        let mut actions = Vec::new();
        verified()
            .finish(Ok(()), true, true, |action| {
                actions.push(action);
                Ok(())
            })
            .unwrap();
        assert_eq!(actions, ["eject"]);
    }
}
