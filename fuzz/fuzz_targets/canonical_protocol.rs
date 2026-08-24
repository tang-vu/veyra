#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value, json};
use veyra_protocol::{canonical_digest, canonical_json};

#[derive(Arbitrary, Debug)]
struct CanonicalInput {
    text: String,
    bytes: Vec<u8>,
    signed: i64,
    unsigned: u64,
    flag: bool,
}

fn assert_canonical_round_trip(value: &Value) {
    let canonical = canonical_json(value).expect("JSON values must be canonicalizable");
    let reparsed: Value =
        serde_json::from_slice(&canonical).expect("canonical JSON must remain valid JSON");
    let second = canonical_json(&reparsed).expect("reparsed JSON must be canonicalizable");
    assert_eq!(canonical, second);

    let digest = canonical_digest(value).expect("JSON values must have a canonical digest");
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(digest, canonical_digest(&reparsed).unwrap());
}

fuzz_target!(|input: CanonicalInput| {
    let lossy_bytes = String::from_utf8_lossy(&input.bytes);
    let mut first = Map::new();
    first.insert("text".into(), Value::String(input.text.clone()));
    first.insert("bytes".into(), Value::String(lossy_bytes.into_owned()));
    first.insert("signed".into(), input.signed.into());
    first.insert("unsigned".into(), input.unsigned.into());
    first.insert("flag".into(), input.flag.into());

    let mut reordered = Map::new();
    for (key, value) in first.iter().rev() {
        reordered.insert(key.clone(), value.clone());
    }

    let first = Value::Object(first);
    let reordered = Value::Object(reordered);
    assert_canonical_round_trip(&first);
    assert_eq!(
        canonical_digest(&first).unwrap(),
        canonical_digest(&reordered).unwrap()
    );

    if let Ok(arbitrary_json) = serde_json::from_slice::<Value>(&input.bytes) {
        assert_canonical_round_trip(&arbitrary_json);
    } else {
        assert_canonical_round_trip(&json!({ "unparsed": input.bytes }));
    }
});
