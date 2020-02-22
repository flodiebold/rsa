

use crate::{pkcs_unpad, PublicKey};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Pow;

pub fn bleichenbacher(msg: &[u8], public_key: &PublicKey, oracle: &impl Fn(Vec<u8>) -> bool) -> Vec<u8> {
    let n = public_key.n.clone();
    let one = BigUint::from(1u32);
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);
    let c = BigUint::from_bytes_be(msg);
    let k = public_key.n.bits().div_ceil(&8);
    let bb: BigUint = two.pow(8*(k-2));
    let bb2 = &two * &bb;
    let bb3 = &three * &bb;
    let bb3m1 = &bb3 - &one;
    let mut s = one.clone();
    let mut i = 1;
    let mut m = vec![(bb2.clone(), bb3m1.clone())];
    assert!(check_s(&c, &one, public_key, oracle));
    while m.len() > 1 || m[0].0 != m[0].1 {
        s = if i == 1 {
            let mut s_1 = n.div_ceil(&bb3);
            while !check_s(&c, &s_1, public_key, oracle) {
                s_1 += &one;
            }
            eprintln!("s_1={}", s_1);
            s_1
        } else if m.len() > 1 {
            let mut s_i = &s + &one;
            while !check_s(&c, &s_i, public_key, oracle) {
                s_i += &one;
            }
            s_i
        } else {
            let (a, b) = m[0].clone();
            let mut r = (&two * (&b * &s - &bb2)).div_ceil(&n);
            'a: loop {
                let mut s_i = (&bb2 + &r * &n).div_ceil(&b);
                let s_max = (&bb3 + &r * &n).div_floor(&a);
                loop {
                    if check_s(&c, &s_i, public_key, oracle) {
                        break 'a s_i;
                    }
                    s_i += &one;
                    if &s_i > &s_max {
                        break;
                    }
                }
                r += &one;
            }
        };

        // we've found our s_i, update intervals
        let mut m_i = Vec::with_capacity(m.len());
        let mut total_size = BigUint::default();
        for (a, b) in m {
            let mut r = (&a * &s - &bb3m1).div_ceil(&n);
            let r_max = (&b * &s - &bb2).div_floor(&n);
            while &r <= &r_max {
                let new_a = (&bb2 + &r * &n).div_ceil(&s).max(a.clone());
                let new_b = (&bb3m1 + &r * &n).div_floor(&s).min(b.clone());
                if &new_a <= &new_b {
                    total_size += &(&new_b - &new_a + &one);
                    m_i.push((new_a, new_b));
                }
                r += &one;
            }
        }

        m = m_i;
        i += 1;

        if i % 50 == 0 {
            eprintln!("i={} |M|={} ||M||={}", i, m.len(), total_size);
        }
    }

    let m = m.pop().unwrap().0;
    pkcs_unpad(m.to_bytes_be(), k).unwrap()
}

fn check_s(c: &BigUint, s: &BigUint, public_key: &PublicKey, oracle: &impl Fn(Vec<u8>) -> bool) -> bool {
    let d = (c * s.modpow(&public_key.e, &public_key.n)) % &public_key.n;
    let bytes = d.to_bytes_be();
    oracle(bytes)
}
