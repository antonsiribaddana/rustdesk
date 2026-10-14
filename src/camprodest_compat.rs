// Keep API account credentials out of the OSS rendezvous protocol.
// Only our pinned Camprodest endpoint gets this compatibility path; other
// servers retain upstream token authentication unchanged.
const SERVER_KEY: &str = "ORnhiBT41kHmj42GxZl5WjJ3v+VJNh1l4d7byY5ugFU=";

pub fn rendezvous_token<'a>(server: &str, key: &str, token: &'a str) -> &'a str {
    let host = server.trim_end_matches(".").split(':').next().unwrap_or("");
    if matches!(host, "camprodest.com" | "connect.camprodest.com") && key == SERVER_KEY {
        ""
    } else {
        token
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_oss_endpoint_uses_device_auth_without_api_token() {
        assert_eq!(rendezvous_token("camprodest.com:21116", SERVER_KEY, "fixture-token"), "");
        assert_eq!(rendezvous_token("connect.camprodest.com:21116", SERVER_KEY, "fixture-token"), "");
    }
    #[test]
    fn unrelated_hosts_and_keys_keep_upstream_authentication() {
        for host in ["example.com:21116", "camprodest.com.example.com", "127.0.0.1:21116"] {
            assert_eq!(rendezvous_token(host, SERVER_KEY, "fixture-token"), "fixture-token");
        }
        assert_eq!(rendezvous_token("camprodest.com:21116", "wrong-key", "fixture-token"), "fixture-token");
        assert_eq!(rendezvous_token("camprodest.com:21116", "", "fixture-token"), "fixture-token");
    }
}
