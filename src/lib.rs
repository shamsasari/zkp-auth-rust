use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

pub struct ChaumPedersen {
    p: BigUint,
    q: BigUint,
    alpha: BigUint,
    beta: BigUint
}

impl ChaumPedersen {
    pub fn generate_pair(&self, exponent: &BigUint) -> (BigUint, BigUint) {
        return (self.alpha.modpow(exponent, &self.p), self.beta.modpow(exponent, &self.p));
    }

    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        return if *k >= c * x {
            (k - c * x) % &self.q
        } else {
            &self.q - (c * x - k) % &self.q
        }
    }

    pub fn verify(&self, r1: &BigUint, r2: &BigUint, y1: &BigUint, y2: &BigUint, c: &BigUint, s: &BigUint) -> bool {
        let (alpha_power_s, beta_power_s) = self.generate_pair(s);
        let calculated_r1 = (alpha_power_s * y1.modpow(c, &self.p)) % &self.p;
        let calculated_r2 = (beta_power_s * y2.modpow(c, &self.p)) % &self.p;
        return *r1 == calculated_r1 && *r2 == calculated_r2
    }
}

pub fn generate_random(limit: &BigUint) -> BigUint {
    return thread_rng().gen_biguint_below(limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_with_hardcoded_values_for_k_and_c() {
        let cp = ChaumPedersen {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            alpha: BigUint::from(4u32),
            beta: BigUint::from(9u32)
        };

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);
        let c = BigUint::from(4u32);

        let (y1, y2) = cp.generate_pair(&x);
        let (r1, r2) = cp.generate_pair(&k);

        let s = cp.solve(&k, &c, &x);
        assert_eq!(s, BigUint::from(5u32));

        let is_verified = cp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(is_verified);
    }

    #[test]
    fn failure_with_attempt_to_mitm() {
        let cp = ChaumPedersen {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            alpha: BigUint::from(4u32),
            beta: BigUint::from(9u32)
        };
        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);
        let c = BigUint::from(4u32);

        let (y1, y2) = cp.generate_pair(&x);
        let (r1, r2) = cp.generate_pair(&k);

        // Man in the middle tries to intercept with a fake secret
        let fake_x = BigUint::from(9u32);
        let fake_s = cp.solve(&k, &c, &fake_x);

        let is_verified = cp.verify(&r1, &r2, &y1, &y2, &c, &fake_s);
        assert!(!is_verified);
    }

    #[test]
    fn success_with_random_values_for_k_and_c() {
        let cp = ChaumPedersen {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            alpha: BigUint::from(4u32),
            beta: BigUint::from(9u32)
        };
        let x = BigUint::from(6u32);
        let k = generate_random(&cp.q);
        let c = generate_random(&cp.q);

        let (y1, y2) = cp.generate_pair(&x);
        let (r1, r2) = cp.generate_pair(&k);

        let s = cp.solve(&k, &c, &x);
        let is_verified = cp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(is_verified);
    }
}
