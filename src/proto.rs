#![deny(unused_must_use)]

use num_bigint::BigUint;

pub trait BigUintExt {
    fn serialise(&self) -> Vec<u8>;
}

impl BigUintExt for BigUint {
    fn serialise(&self) -> Vec<u8> {
        self.to_bytes_be()
    }
}

pub trait Vecu8Ext {
    fn deserialise_big_uint(&self) -> BigUint;
}

impl Vecu8Ext for Vec<u8> {
    fn deserialise_big_uint(&self) -> BigUint {
        BigUint::from_bytes_be(self)
    }
}
