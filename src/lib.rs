use num_bigint::BigUint;

pub fn solve(k: &BigUint, c: &BigUint, x: &BigUint, q: &BigUint) -> BigUint {
    // TODO Do we need modpow?
    return if *k >= c * x {
        (k - c * x) % q
    } else {
        q - (c * x - k) % q
    }
}

pub fn verify(
    r1: &BigUint, r2: &BigUint,
    y1: &BigUint, y2: &BigUint,
    alpha: &BigUint,
    beta: &BigUint,
    c: &BigUint,
    s: &BigUint,
    p: &BigUint
) -> bool {
    let calculated_r1 = (alpha.modpow(s, p) * y1.modpow(c, p)) % p;
    let calculate_r2 = (beta.modpow(s, p) * y2.modpow(c, p)) % p;
    return *r1 == calculated_r1 && *r2 == calculate_r2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_success() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);
        let c = BigUint::from(4u32);

        let y1 = alpha.modpow(&x, &p);
        let y2 = beta.modpow(&x, &p);

        let r1 = alpha.modpow(&k, &p);
        let r2 = beta.modpow(&k, &p);

        let s = solve(&k, &c, &x, &q);
        assert_eq!(s, BigUint::from(5u32));

        let is_verified = verify(&r1, &r2, &y1, &y2, &alpha, &beta, &c, &s, &p);
        assert!(is_verified);
    }

    #[test]
    fn basic_failure() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);
        let c = BigUint::from(4u32);

        let y1 = alpha.modpow(&x, &p);
        let y2 = beta.modpow(&x, &p);

        let r1 = alpha.modpow(&k, &p);
        let r2 = beta.modpow(&k, &p);

        // Man in the middle tries to intercept with a fake secret
        let fake_x = BigUint::from(9u32);
        let fake_s = solve(&k, &c, &fake_x, &q);

        let is_verified = verify(&r1, &r2, &y1, &y2, &alpha, &beta, &c, &fake_s, &p);
        assert!(!is_verified);
    }
}
