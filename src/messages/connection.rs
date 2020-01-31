use serde::{Deserialize, Serialize};

/// Invitation message usually base64 encoded to begin the
/// connection process
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invitation {
    #[serde(skip_serializing_if = "Option::is_none")]
    did: Option<String>,
    #[serde(rename = "@id", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    label: String,
    #[serde(rename = "@type")]
    msg_type: String,
    #[serde(rename = "recipientKeys")]
    recipient_keys: Option<Vec<String>>,
    #[serde(rename = "routingKeys", skip_serializing_if = "Option::is_none")]
    routing_keys: Option<Vec<String>>,
    #[serde(rename = "serviceEndpoint", skip_serializing_if = "Option::is_none")]
    service_endpoint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_tests() {
        let res: serde_json::Result<Invitation> = serde_json::from_str(
            r##"{
            "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
            "@id": "12345678900987654321",
            "label": "Alice",
            "did": "did:sov:QmWbsNYhMrjHiqZDTUTEJs"
        }"##,
        );
        assert!(res.is_ok());
        let invite = res.unwrap();
        assert_eq!(
            invite.did,
            Some("did:sov:QmWbsNYhMrjHiqZDTUTEJs".to_string())
        );
        assert_eq!(invite.id, Some("12345678900987654321".to_string()));
        assert_eq!(invite.label, "Alice");
        assert_eq!(
            invite.msg_type,
            "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation"
        );
        assert!(invite.recipient_keys.is_none());
        assert!(invite.routing_keys.is_none());
        assert!(invite.service_endpoint.is_none());

        let res: serde_json::Result<Invitation> = serde_json::from_str(
            r##"{
            "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
            "@id": "12345678900987654321",
            "label": "Alice",
            "recipientKeys": ["8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"],
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"]
        }"##,
        );
        assert!(res.is_ok());
        let invite = res.unwrap();
        assert!(invite.did.is_none());
        assert_eq!(invite.id, Some("12345678900987654321".to_string()));
        assert_eq!(invite.label, "Alice");
        assert_eq!(
            invite.msg_type,
            "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation"
        );
        assert_eq!(
            invite.recipient_keys,
            Some(vec![
                "8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K".to_string()
            ])
        );
        assert_eq!(
            invite.routing_keys,
            Some(vec![
                "8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K".to_string()
            ])
        );
        assert_eq!(
            invite.service_endpoint,
            Some("https://example.com/endpoint".to_string())
        );

        let res: serde_json::Result<Invitation> = serde_json::from_str(
            r##"{
            "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
            "label": "Alice",
            "recipientKeys": ["8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"],
            "serviceEndpoint": "did:sov:A2wBhNYhMrjHiqZDTUYH7u;routeid",
            "routingKeys": ["8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"]
        }"##,
        );
        assert!(res.is_ok());
        let invite = res.unwrap();
        assert!(invite.did.is_none());
        assert!(invite.id.is_none());
        assert_eq!(invite.label, "Alice");
        assert_eq!(
            invite.msg_type,
            "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation"
        );
        assert_eq!(
            invite.recipient_keys,
            Some(vec![
                "8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K".to_string()
            ])
        );
        assert_eq!(
            invite.routing_keys,
            Some(vec![
                "8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K".to_string()
            ])
        );
        assert_eq!(
            invite.service_endpoint,
            Some("did:sov:A2wBhNYhMrjHiqZDTUYH7u;routeid".to_string())
        );
    }
}
