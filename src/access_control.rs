// Camprodest access control (studio side).
//
// Each studio PC periodically fetches its own allow-list from the Camprodest
// access panel and refuses any incoming connection whose id is not currently
// permitted (manager toggle off, or outside the assigned shift window). This is
// the enforcement layer behind the panel at connect.camprodest.com/access.
//
// It is a no-op unless CAMPRODEST_ACCESS_URL + CAMPRODEST_ACCESS_TOKEN are baked
// in at build time, so upstream / non-Camprodest builds are completely unaffected.

use hbb_common::{config::Config, lazy_static, log, tokio};
use std::{
    collections::HashSet,
    sync::RwLock,
    time::{Duration, Instant},
};

// Baked at build time (like the rendezvous server + public key).
const ACCESS_URL: Option<&str> = option_env!("CAMPRODEST_ACCESS_URL");
const ACCESS_TOKEN: Option<&str> = option_env!("CAMPRODEST_ACCESS_TOKEN");

const REFRESH: Duration = Duration::from_secs(10);
// If we cannot reach the panel for longer than this, fail closed (deny) so a
// machine that loses network can't be used indefinitely out of hours.
const STALE_DENY: Duration = Duration::from_secs(300);

pub const DENY_MSG: &str =
    "Access is not enabled for your account right now. Ask your manager to turn it on.";

struct Policy {
    allow: HashSet<String>,
    // Whether the manager has armed this studio. Until armed, we behave exactly
    // like stock RustDesk (allow everyone) so a rolled-out client can never lock
    // a studio out just because its allow-list happens to be empty.
    enforced: bool,
    fetched: bool,
    at: Instant,
}

lazy_static::lazy_static! {
    static ref POLICY: RwLock<Policy> = RwLock::new(Policy {
        allow: HashSet::new(),
        enforced: false,
        fetched: false,
        at: Instant::now(),
    });
    // Connection attempts waiting to be reported to the panel (drained each cycle).
    static ref REPORTS: RwLock<Vec<(String, String, String)>> = RwLock::new(Vec::new()); // (peer_id, action, reason)
}

pub fn enabled() -> bool {
    matches!((ACCESS_URL, ACCESS_TOKEN), (Some(u), Some(t)) if !u.is_empty() && !t.is_empty())
}

/// Synchronous check used on the connection hot path. Returns true when the
/// connecting `peer_id` is currently allowed to control this studio PC.
pub fn is_allowed(peer_id: &str) -> bool {
    if !enabled() {
        return true; // access control not configured -> behave like stock RustDesk
    }
    let p = match POLICY.read() {
        Ok(p) => p,
        Err(_) => return true, // lock guard poisoned -> don't lock the studio out
    };
    if !p.fetched {
        return true; // startup grace before the first policy fetch
    }
    if !p.enforced {
        return true; // studio not armed by the manager -> stock behaviour
    }
    if p.at.elapsed() > STALE_DENY {
        return false; // armed studio, offline too long -> fail closed
    }
    p.allow.contains(peer_id)
}

/// Queue an allow/deny event for the panel's activity log (non-blocking).
pub fn report(peer_id: &str, action: &str, reason: &str) {
    if !enabled() {
        return;
    }
    if let Ok(mut r) = REPORTS.write() {
        if r.len() < 1000 {
            r.push((peer_id.to_string(), action.to_string(), reason.to_string()));
        }
    }
}

/// Start the background refresher. Safe to call always; does nothing when the
/// access URL/token were not baked in.
pub fn start() {
    if !enabled() {
        return;
    }
    std::thread::spawn(|| {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("access_control: runtime error: {e}");
                return;
            }
        };
        rt.block_on(run());
    });
}

async fn run() {
    let base = ACCESS_URL.unwrap_or("").trim_end_matches('/').to_string();
    let token = ACCESS_TOKEN.unwrap_or("").to_string();
    // The display name reported to the panel (account.txt name → operator user →
    // hostname). Only reported when the app is actually INSTALLED, so CI builds,
    // portable/dev runs and test machines never register themselves as studios.
    let name = if crate::platform::is_installed() {
        crate::common::preset_display_name()
    } else {
        None
    };
    loop {
        let own_id = Config::get_id();
        if !own_id.is_empty() {
            fetch_policy(&base, &token, &own_id, name.as_deref()).await;
            flush_reports(&base, &token, &own_id).await;
        }
        tokio::time::sleep(REFRESH).await;
    }
}

async fn fetch_policy(base: &str, token: &str, own_id: &str, name: Option<&str>) {
    let url = format!("{base}/api/policy/{own_id}");
    let client = crate::hbbs_http::create_http_client_async_with_url(&url).await;
    let mut req = client.get(&url).header("x-access-token", token);
    // reqwest url-encodes the query value (handles spaces / unicode names).
    if let Some(n) = name.filter(|n| !n.is_empty()) {
        req = req.query(&[("name", n)]);
    }
    match req.send().await {
        Ok(resp) => match resp.text().await {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let allow: HashSet<String> = v
                        .get("allow")
                        .and_then(|a| a.as_array())
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    let enforced = v.get("enforced").and_then(|e| e.as_bool()).unwrap_or(false);
                    if let Ok(mut p) = POLICY.write() {
                        p.allow = allow;
                        p.enforced = enforced;
                        p.fetched = true;
                        p.at = Instant::now();
                    }
                }
            }
            Err(e) => log::debug!("access_control: read policy failed: {e}"),
        },
        Err(e) => log::debug!("access_control: fetch policy failed: {e}"),
    }
}

async fn flush_reports(base: &str, token: &str, own_id: &str) {
    let pending: Vec<(String, String, String)> = {
        match REPORTS.write() {
            Ok(mut r) => std::mem::take(&mut *r),
            Err(_) => return,
        }
    };
    if pending.is_empty() {
        return;
    }
    let url = format!("{base}/api/report");
    let client = crate::hbbs_http::create_http_client_async_with_url(&url).await;
    for (peer_id, action, reason) in pending {
        let body = serde_json::json!({
            "studioId": own_id,
            "employeeId": peer_id,
            "action": action,
            "reason": reason,
        });
        let _ = client
            .post(&url)
            .header("x-access-token", token)
            .json(&body)
            .send()
            .await;
    }
}
