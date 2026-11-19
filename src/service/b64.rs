//! Base64 (standard alphabet) for binary fields in JSON, as `#[serde(with = ...)]`.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};
use zeroize::Zeroizing;

pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&STANDARD.encode(v))
}

struct B64;

impl Visitor<'_> for B64 {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a base64 string")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
        STANDARD.decode(v).map_err(E::custom)
    }
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    d.deserialize_str(B64)
}

pub(crate) fn deserialize_secret<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Zeroizing<Vec<u8>>, D::Error> {
    deserialize(d).map(Zeroizing::new)
}
