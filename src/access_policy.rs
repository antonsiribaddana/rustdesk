//! Pure policy decision shared by login and live-session checks.

use std::time::Duration;

pub(crate) const STALE_DENY: Duration = Duration::from_secs(300);

pub(crate) fn permits(
    fetched: bool,
    enforced: bool,
    age: Duration,
    listed: bool,
    now_ms: u64,
    valid_until_ms: Option<u64>,
) -> bool {
    // Configured clients must obtain a policy before accepting connections.
    if !fetched {
        return false;
    }
    if !enforced {
        return true;
    }
    if age >= STALE_DENY || !listed {
        return false;
    }
    valid_until_ms.map_or(true, |end| now_ms < end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_startup_grace_for_configured_clients() {
        assert!(!permits(false, false, Duration::ZERO, true, 0, None));
    }

    #[test]
    fn unarmed_studio_retains_native_authentication() {
        assert!(permits(true, false, STALE_DENY, false, 0, None));
    }

    #[test]
    fn scheduled_access_expires_at_exact_boundary_even_with_fresh_cache() {
        assert!(permits(true, true, Duration::ZERO, true, 1999, Some(2000)));
        assert!(!permits(true, true, Duration::ZERO, true, 2000, Some(2000)));
        assert!(!permits(true, true, Duration::ZERO, true, 2001, Some(2000)));
    }

    #[test]
    fn no_schedule_or_revoked_peer_stays_denied() {
        assert!(!permits(true, true, Duration::ZERO, false, 1500, Some(2000)));
    }

    #[test]
    fn managers_have_no_shift_deadline_but_cannot_use_stale_policy() {
        assert!(permits(true, true, Duration::ZERO, true, 999999, None));
        assert!(!permits(true, true, STALE_DENY, true, 999999, None));
    }
}
