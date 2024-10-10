use std::str::FromStr;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SkdeParams {
    pub n: BigUint, // RSA modulus n = p * q
    pub g: BigUint, // group generator
    pub t: u32,     // delay parameter
    pub h: BigUint, // g^{2^t} mod n

    pub max_sequencer_number: BigUint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey {
    pub pk: BigUint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecretKey {
    pub sk: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CipherPair {
    pub c1: String,
    pub c2: String,
}

impl std::fmt::Display for CipherPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}{}", self.c1, Self::DELIMITER, self.c2)
    }
}

impl FromStr for CipherPair {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (c1, c2) = s
            .split_once(Self::DELIMITER)
            .ok_or(ParseError::MissingDelimiter(Self::DELIMITER))?;

        if c1.is_empty() || c2.is_empty() {
            return Err(ParseError::InvalidFormat);
        }

        Ok(Self {
            c1: c1.to_owned(),
            c2: c2.to_owned(),
        })
    }
}

impl CipherPair {
    const DELIMITER: &'static str = ";";
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ciphertext(Vec<CipherPair>);

impl std::fmt::Display for Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0
            .iter()
            .try_for_each(|cipher_pair| write!(f, "{}{}", cipher_pair, Self::TERMINATOR))
    }
}

impl From<Vec<CipherPair>> for Ciphertext {
    fn from(value: Vec<CipherPair>) -> Self {
        Self(value)
    }
}

impl FromStr for Ciphertext {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ciphertext = Vec::<CipherPair>::new();

        for (index, cipher_pair_str) in s.split_terminator(Self::TERMINATOR).enumerate() {
            let cipher_pair = CipherPair::from_str(cipher_pair_str)
                .map_err(|error| ParseError::Ciphertext(index, Box::new(error)))?;
            ciphertext.push(cipher_pair);
        }

        Ok(ciphertext.into())
    }
}

impl Ciphertext {
    const TERMINATOR: &'static str = "/";

    pub fn iter(&self) -> core::slice::Iter<'_, CipherPair> {
        self.0.iter()
    }
}

#[derive(Debug)]
pub enum ParseError {
    MissingDelimiter(&'static str),
    InvalidFormat,
    Ciphertext(usize, Box<Self>),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ParseError {}
