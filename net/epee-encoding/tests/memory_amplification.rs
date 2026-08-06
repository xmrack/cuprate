//! Regression tests for the container element-count cap that prevents a memory-amplification OOM.
//!
//! Unlike `out_of_memory.rs` (which claims a huge length with *no* backing bytes, so the read loop
//! errors on the first missing element), these tests cover the amplification where an attacker
//! *does* supply the backing bytes: a `Vec` of many one-byte elements of a type whose in-memory size
//! greatly exceeds its minimum encoded size (e.g. `bytes::Bytes` is 32 bytes in memory but an empty
//! `Bytes` encodes in a single byte). Without the cap, a small message could force a multi-GB
//! allocation.
#![expect(unused_crate_dependencies)]

use cuprate_epee_encoding::{epee_object, from_bytes};

struct T {
    a: Vec<bytes::Bytes>,
}

epee_object!(
    T,
    a: Vec<bytes::Bytes>,
);

/// Build a `T` message whose `a` field claims `n_elements` byte-strings, followed by
/// `backing_zero_bytes` of `0x00` (each decoding as an empty `Bytes`).
fn body_claiming(n_elements: u64, backing_zero_bytes: usize) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    // epee header
    data.extend_from_slice(&[0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01]);
    data.push(0x04); // root object: 1 field
    data.push(0x01);
    data.push(b'a'); // field name "a"
    data.push(0x80 | 0x0a); // marker: sequence-of-string (Bytes)
                            // sequence length as an 8-byte epee varint: (n << 2) | 3, little-endian
    let vi: u64 = (n_elements << 2) | 0b11;
    data.extend_from_slice(&vi.to_le_bytes());
    data.extend(std::iter::repeat(0u8).take(backing_zero_bytes));
    data
}

/// A huge claimed element count must be rejected by the element-count cap, *before* any large
/// allocation — even though (in the real attack) the backing bytes would be supplied.
#[test]
fn huge_element_count_is_rejected() {
    let data = body_claiming(100_000_000, 0);
    assert!(
        from_bytes::<T, _>(&mut data.as_slice()).is_err(),
        "a 100M-element container claim must be rejected by the element-count cap"
    );
}

/// A legitimate small container with real backing bytes must still decode correctly.
#[test]
fn legit_small_container_decodes() {
    let data = body_claiming(3, 3); // three empty byte-strings
    let decoded: T = from_bytes(&mut data.as_slice()).expect("a valid small Vec<Bytes> must decode");
    assert_eq!(decoded.a.len(), 3);
}
