#![allow(non_snake_case, unused)]
use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    pub static ref TlsAlerts: HashMap<u8, &'static str> = {
        let mut m = HashMap::new();
        m.insert(0, "close_notify"); // [RFC8446][RFC
        m.insert(10, "unexpected_message"); // [RFC8446]
        m.insert(20, "bad_record_mac"); // [RFC8446]
        m.insert(21, "decryption_failed_RESERVED"); // [RFC8446]
        m.insert(22, "record_overflow"); // [RFC8446]
        m.insert(30, "decompression_failure_RESERVED"); // [RFC8446]
        m.insert(40, "handshake_failure"); // [RFC8446]
        m.insert(41, "no_certificate_RESERVED"); // [RFC8446]
        m.insert(42, "bad_certificate"); // [RFC8446]
        m.insert(43, "unsupported_certificate"); // [RFC8446]
        m.insert(44, "certificate_revoked"); // [RFC8446]
        m.insert(45, "certificate_expired"); // [RFC8446]
        m.insert(46, "certificate_unknown"); // [RFC8446]
        m.insert(47, "illegal_parameter"); // [RFC8446]
        m.insert(48, "unknown_ca"); // [RFC8446]
        m.insert(49, "access_denied"); // [RFC8446]
        m.insert(50, "decode_error"); // [RFC8446]
        m.insert(51, "decrypt_error"); // [RFC8446]
        m.insert(52, "too_many_cids_requested"); // [RFC9147]
        m.insert(60, "export_restriction_RESERVED"); // [RFC8446]
        m.insert(70, "protocol_version"); // [RFC8446]
        m.insert(71, "insufficient_security"); // [RFC8446]
        m.insert(80, "internal_error"); // [RFC8446]
        m.insert(86, "inappropriate_fallback"); // [RFC7507]
        m.insert(90, "user_canceled"); // [RFC8446]
        m.insert(100, "no_renegotiation_RESERVED"); // [RFC8446]
        m.insert(109, "missing_extension"); // [RFC8446]
        m.insert(110, "unsupported_extension"); // [RFC8446]
        m.insert(111, "certificate_unobtainable_RESERVED"); // [RFC6066][RFC8446]
        m.insert(112, "unrecognized_name"); // [RFC6066]
        m.insert(113, "bad_certificate_status_response"); // [RFC6066]
        m.insert(114, "bad_certificate_hash_value_RESERVED"); // [RFC6066][RFC8446]
        m.insert(115, "unknown_psk_identity"); // [RFC4279]
        m.insert(116, "certificate_required"); // [RFC8446]
        m.insert(120, "no_application_protocol"); // [RFC7301][RFC8447]
        m
    };
}
