// SPDX-License-Identifier: MIT
use base64::{Engine, engine::general_purpose::STANDARD};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn field(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self
            .data
            .get(self.position..self.position + 4)
            .ok_or_else(|| Error("public-key-truncated".into()))?;
        let size = u32::from_be_bytes(n.try_into().unwrap()) as usize;
        self.position += 4;
        require(size > 0 && size <= max, "public-key-field-bound")?;
        let value = self
            .data
            .get(self.position..self.position + size)
            .ok_or_else(|| Error("public-key-field-bound".into()))?;
        self.position += size;
        Ok(value)
    }
    fn integer(&mut self) -> Result<&'a [u8]> {
        let v = self.field(2048)?;
        require(
            v[0] & 0x80 == 0 && !(v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0),
            "public-key-integer-invalid",
        )?;
        Ok(v)
    }
}
pub fn public_key(value: &str) -> Result<Value> {
    require(
        !value.is_empty() && value.len() <= 16384 && !value.chars().any(|c| (c as u32) < 32),
        "public-key-input-invalid",
    )?;
    let fields = value.split_whitespace().collect::<Vec<_>>();
    require((2..=32).contains(&fields.len()), "public-key-input-invalid")?;
    let (name, encoded) = (fields[0], fields[1]);
    let blob = STANDARD
        .decode(encoded)
        .map_err(|_| Error("public-key-encoding-invalid".into()))?;
    require(!blob.is_empty() && blob.len() <= 8192, "public-key-bound")?;
    let mut reader = Reader {
        data: &blob,
        position: 0,
    };
    require(
        reader.field(128)? == name.as_bytes(),
        "public-key-type-mismatch",
    )?;
    let hardware = name.starts_with("sk-");
    match name {
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => {
            require(reader.field(32)?.len() == 32, "public-key-ed25519-size")?
        }
        "ssh-rsa" => {
            let exponent = reader.integer()?;
            let exponent = exponent
                .iter()
                .try_fold(0u64, |v, b| {
                    v.checked_mul(256).and_then(|v| v.checked_add(*b as u64))
                })
                .ok_or_else(|| Error("public-key-rsa-strength".into()))?;
            let modulus = reader.integer()?;
            let first = modulus
                .iter()
                .position(|b| *b != 0)
                .ok_or_else(|| Error("public-key-rsa-strength".into()))?;
            let bits =
                (modulus.len() - first - 1) * 8 + (8 - modulus[first].leading_zeros() as usize);
            require(
                (3..=u32::MAX as u64).contains(&exponent)
                    && exponent % 2 == 1
                    && (3072..=8192).contains(&bits)
                    && modulus.last().unwrap() & 1 == 1,
                "public-key-rsa-strength",
            )?;
        }
        n if n.starts_with("ecdsa-sha2-") || n == "sk-ecdsa-sha2-nistp256@openssh.com" => {
            let curve = reader.field(32)?;
            let expected = if hardware {
                "nistp256"
            } else {
                n.strip_prefix("ecdsa-sha2-").unwrap()
            };
            let length = match curve {
                b"nistp256" => 65,
                b"nistp384" => 97,
                b"nistp521" => 133,
                _ => 0,
            };
            let point = reader.field(133)?;
            require(
                curve == expected.as_bytes() && point.len() == length && point[0] == 4,
                "public-key-curve-invalid",
            )?;
        }
        _ => return Err(Error("public-key-type-unsupported".into())),
    }
    if hardware {
        require(
            reader.field(1024)?.iter().all(|c| (32..=126).contains(c)),
            "public-key-application-invalid",
        )?;
    }
    require(reader.position == blob.len(), "public-key-trailing-data")?;
    Ok(
        json!({"key":format!("{name} {}", STANDARD.encode(&blob)),"fingerprint":format!("SHA256:{}",STANDARD.encode(Sha256::digest(&blob)).trim_end_matches('=')),"type":name,"hardware_backed":hardware}),
    )
}
pub fn key_list(values: &Value) -> Result<Vec<Value>> {
    let values = values
        .as_array()
        .ok_or_else(|| Error("public-key-list-bound".into()))?;
    require((1..=32).contains(&values.len()), "public-key-list-bound")?;
    let mut seen = BTreeSet::new();
    values
        .iter()
        .map(|v| {
            let row = public_key(
                v.as_str()
                    .ok_or_else(|| Error("public-key-input-invalid".into()))?,
            )?;
            require(
                seen.insert(row["fingerprint"].as_str().unwrap().to_owned()),
                "public-key-duplicate",
            )?;
            Ok(row)
        })
        .collect()
}
