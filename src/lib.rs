#![deny(unused_must_use)]

use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

#[derive(Debug, Default)]  // TODO Shouldn't really be Default
pub struct ChaumPedersen {
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
    pub h: BigUint
}

impl ChaumPedersen {
    pub fn generate_pair(&self, exponent: &BigUint) -> (BigUint, BigUint) {
        (self.g.modpow(exponent, &self.p), self.h.modpow(exponent, &self.p))
    }

    pub fn generate_q_random(&self) -> BigUint {
        thread_rng().gen_biguint_below(&self.q)
    }

    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        if *k >= c * x {
            (k - c * x) % &self.q
        } else {
            &self.q - (c * x - k) % &self.q
        }
    }

    pub fn verify(&self, r1: &BigUint, r2: &BigUint, y1: &BigUint, y2: &BigUint, c: &BigUint, s: &BigUint) -> Result<(), &str> {
        let (g_power_s, h_power_s) = self.generate_pair(s);
        let calculated_r1 = (g_power_s * y1.modpow(c, &self.p)) % &self.p;
        if *r1 != calculated_r1 {
            return Err("r1 value does not match");
        }
        let calculated_r2 = (h_power_s * y2.modpow(c, &self.p)) % &self.p;
        if *r2 != calculated_r2 {
            return Err("r2 value does not match");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use num::Num;

    use super::*;

    #[test]
    fn success_with_hardcoded_values_for_k_and_c() {
        let cp = ChaumPedersen {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            g: BigUint::from(4u32),
            h: BigUint::from(9u32)
        };

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);
        let c = BigUint::from(4u32);

        let (y1, y2) = cp.generate_pair(&x);
        let (r1, r2) = cp.generate_pair(&k);

        let s = cp.solve(&k, &c, &x);
        assert_eq!(s, BigUint::from(5u32));

        let result = cp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result.is_ok());
    }

    #[test]
    fn failure_with_attempt_to_mitm() {
        let cp = ChaumPedersen {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            g: BigUint::from(4u32),
            h: BigUint::from(9u32)
        };
        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);
        let c = BigUint::from(4u32);

        let (y1, y2) = cp.generate_pair(&x);
        let (r1, r2) = cp.generate_pair(&k);

        // Man in the middle tries to intercept with a fake secret
        let fake_x = BigUint::from(9u32);
        let fake_s = cp.solve(&k, &c, &fake_x);

        let result = cp.verify(&r1, &r2, &y1, &y2, &c, &fake_s);
        assert!(result.is_err());
    }

    #[test]
    fn success_with_random_values_for_k_and_c() {
        let cp = ChaumPedersen {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            g: BigUint::from(4u32),
            h: BigUint::from(9u32)
        };
        let x = BigUint::from(6u32);
        let k = cp.generate_q_random();
        let c = cp.generate_q_random();

        let (y1, y2) = cp.generate_pair(&x);
        let (r1, r2) = cp.generate_pair(&k);

        let s = cp.solve(&k, &c, &x);
        let result = cp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result.is_ok());
    }

    #[test]
    fn success_on_rfc_5114_suggested_group() {
        // Values taken from https://datatracker.ietf.org/doc/html/rfc5114#section-2.1
        let p = BigUint::from_str_radix(
            "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61\
                6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF\
                ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0\
                A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
            16
        ).unwrap();
        let g = BigUint::from_str_radix(
            "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31\
                266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4\
                D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A\
                D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
            16
        ).unwrap();
        let q = BigUint::from_str_radix("F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16).unwrap();
        let cp = ChaumPedersen {
            p: p.clone(),
            q: q.clone(),
            g: g.clone(),
            // alpha^i is also a generator
            h: g.modpow(&generate_random(&q), &p)
        };
        let x = generate_random(&cp.q);
        let k = cp.generate_q_random();
        let c = cp.generate_q_random();

        let (y1, y2) = cp.generate_pair(&x);
        let (r1, r2) = cp.generate_pair(&k);

        let s = cp.solve(&k, &c, &x);
        let result = cp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result.is_ok());
    }

    fn generate_random(limit: &BigUint) -> BigUint {
        return thread_rng().gen_biguint_below(limit)
    }
}
