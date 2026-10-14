//! Account-authenticated, challenge-bound scheduled login. The account bearer
//! token goes only to Studio over TLS; the peer receives a single-use grant.
use hbb_common::{
    config::{Config, LocalConfig},
    message_proto::{Hash, LoginRequest},
    protobuf::UnknownValueRef,
    sha2::{Digest, Sha256},
};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

// Reserved Camprodest protobuf extension; does not alter upstream fields or
// trust-device HWIDs. Old clients ignore it and cannot use scheduled login.
const GRANT_FIELD: u32 = 1001;
const URL: Option<&str> = option_env!("CAMPRODEST_CONNECT_AUTH_URL");
const HOST_TOKEN: Option<&str> = option_env!("CAMPRODEST_CONNECT_HOST_TOKEN");
const DENIED: &str = "Scheduled access could not be verified. Sign into your linked Connect account and check your approved shift.";

pub(crate) fn enabled() -> bool {
    URL.is_some_and(|url| url.starts_with("https://connect.camprodest.com/") && !url.contains('?') && !url.contains('#'))
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Binding {
    source_peer_id: String,
    target_peer_id: String,
    challenge: String,
    connection_id: String,
}

fn binding(source: String, target: String, hash: &Hash, connection_id: u64) -> Binding {
    let challenge = format!("{:x}", Sha256::digest(format!("{}:{}", hash.salt, hash.challenge).as_bytes()));
    Binding { source_peer_id: source, target_peer_id: target, challenge, connection_id: connection_id.to_string() }
}

async fn post(path: &str, body: Value, bearer: Option<&str>) -> Result<Value, &'static str> {
    if !enabled() { return Err(DENIED); }
    let url = format!("{}/{}", URL.unwrap_or("").trim_end_matches('/'), path);
    // No invalid-cert overrides or cross-origin redirects for account tokens.
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3)).build().map_err(|_| DENIED)?;
    let mut request = client.post(url).json(&body);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    } else {
        let token = HOST_TOKEN.filter(|token| token.len() >= 32).ok_or(DENIED)?;
        request = request.header("x-connect-host-token", token);
    }
    let response = request.send().await.map_err(|_| DENIED)?;
    if !response.status().is_success() { return Err(DENIED); }
    let value: Value = response.json().await.map_err(|_| DENIED)?;
    if value.get("success").and_then(Value::as_bool) != Some(true) { return Err(DENIED); }
    Ok(value)
}

fn secret(value: &Value, field: &str) -> Result<String, &'static str> {
    let result = value.get(field).and_then(Value::as_str).ok_or(DENIED)?;
    if result.len() != 64 || !result.bytes().all(|byte| byte.is_ascii_hexdigit()) { return Err(DENIED); }
    Ok(result.to_owned())
}

pub(crate) async fn request(target: &str, hash: &Hash, connection_id: u64) -> Result<String, &'static str> {
    let token = LocalConfig::get_option("access_token");
    if token.is_empty() { return Err(DENIED); }
    let bound = binding(Config::get_id(), target.to_owned(), hash, connection_id);
    let value = post("grants", json!(bound), Some(&token)).await?;
    secret(&value, "grant")
}

pub(crate) fn attach(lr: &mut LoginRequest, grant: String) {
    lr.special_fields.mut_unknown_fields().add_length_delimited(GRANT_FIELD, grant.into_bytes());
}

pub(crate) struct Lease {
    bound: Binding,
    token: String,
    at: Instant,
    duration: Duration,
}

fn duration(value: &Value) -> Result<Duration, &'static str> {
    let ms = value.get("validForMs").and_then(Value::as_u64).filter(|ms| *ms > 0 && *ms <= 10000).ok_or(DENIED)?;
    Ok(Duration::from_millis(ms))
}

pub(crate) async fn consume(lr: &LoginRequest, hash: &Hash) -> Result<Lease, &'static str> {
    let grant = match lr.special_fields.unknown_fields().get(GRANT_FIELD) {
        Some(UnknownValueRef::LengthDelimited(bytes)) if bytes.len() == 64 => std::str::from_utf8(bytes).map_err(|_| DENIED)?,
        _ => return Err(DENIED),
    };
    if !grant.bytes().all(|byte| byte.is_ascii_hexdigit()) { return Err(DENIED); }
    let bound = binding(lr.my_id.clone(), Config::get_id(), hash, lr.session_id);
    let mut body = json!(bound); body["grant"] = json!(grant);
    let value = post("consume", body, None).await?;
    Ok(Lease { bound, token: secret(&value, "lease")?, at: Instant::now(), duration: duration(&value)? })
}

impl Lease {
    pub(crate) async fn permitted(&mut self) -> bool {
        if self.at.elapsed() >= self.duration { return false; }
        if self.duration.saturating_sub(self.at.elapsed()) > Duration::from_secs(5) { return true; }
        let mut body = json!(self.bound); body["lease"] = json!(self.token);
        match post("lease", body, None).await.and_then(|value| duration(&value)) {
            Ok(duration) => { self.at = Instant::now(); self.duration = duration; true }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::protobuf::Message;

    #[test]
    fn grant_round_trips_as_extension_without_changing_password_or_hwid() {
        let mut lr = LoginRequest::new();
        lr.my_id = "111111111".into();
        let grant = "a".repeat(64);
        attach(&mut lr, grant.clone());
        let restored = LoginRequest::parse_from_bytes(&lr.write_to_bytes().unwrap()).unwrap();
        assert!(restored.password.is_empty());
        assert!(restored.hwid.is_empty());
        assert_eq!(restored.special_fields.unknown_fields().get(GRANT_FIELD),
            Some(UnknownValueRef::LengthDelimited(grant.as_bytes())));
    }

    #[test]
    fn binding_changes_with_target_challenge_and_connection() {
        let hash = Hash { salt: "sample-salt".into(), challenge: "sample-challenge".into(), ..Default::default() };
        let first = binding("111111111".into(), "222222222".into(), &hash, 1);
        assert_eq!(first.challenge.len(), 64);
        let other = Hash { challenge: "different-challenge".into(), ..hash.clone() };
        assert_ne!(first.challenge, binding("111111111".into(), "222222222".into(), &other, 1).challenge);
        assert_ne!(first.connection_id, binding("111111111".into(), "222222222".into(), &hash, 2).connection_id);
    }

    #[test]
    fn invalid_or_unbounded_lease_is_rejected() {
        for value in [json!({}), json!({"validForMs": 0}), json!({"validForMs": 10001}), json!({"validForMs": -1})] {
            assert!(duration(&value).is_err());
        }
        assert_eq!(duration(&json!({"validForMs": 1234})).unwrap(), Duration::from_millis(1234));
    }
}
