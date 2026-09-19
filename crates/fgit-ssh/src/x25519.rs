#![forbid(unsafe_code)]

//! Clean-room, pure-Rust RFC 7748 X25519 Diffie-Hellman primitive.
//!
//! Provides constant-time scalar multiplication over Curve25519
//! without external dependencies or derive macros.

const BASE_POINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Self = Self([0, 0, 0, 0, 0]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);
    const A24: Self = Self([121_665, 0, 0, 0, 0]);

    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut b = *bytes;
        b[31] &= 0x7f; // mask 255th bit per RFC 7748 section 5

        let load64 = |offset: usize| -> u64 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&b[offset..offset + 8]);
            u64::from_le_bytes(arr)
        };

        let w0 = load64(0);
        let w1 = load64(6);
        let w2 = load64(12);
        let w3 = load64(19);
        let w4 = load64(24);

        Self([
            w0 & 0x0007_ffff_ffff_ffff,
            (w1 >> 3) & 0x0007_ffff_ffff_ffff,
            (w2 >> 6) & 0x0007_ffff_ffff_ffff,
            (w3 >> 1) & 0x0007_ffff_ffff_ffff,
            (w4 >> 12) & 0x0007_ffff_ffff_ffff,
        ])
    }

    fn carry(&mut self) {
        let mask = 0x0007_ffff_ffff_ffff;
        let mut c = 0u64;
        for limb in &mut self.0 {
            let sum = *limb + c;
            *limb = sum & mask;
            c = sum >> 51;
        }
        let sum0 = self.0[0] + c * 19;
        self.0[0] = sum0 & mask;
        c = sum0 >> 51;
        for limb in self.0.iter_mut().skip(1) {
            let sum = *limb + c;
            *limb = sum & mask;
            c = sum >> 51;
        }
        self.0[0] += c * 19;
    }

    fn to_bytes(mut self) -> [u8; 32] {
        self.carry();
        self.carry();

        // Check if self >= 2^255 - 19
        let mut c = 19u64;
        for limb in &self.0 {
            c = (*limb + c) >> 51;
        }

        if c != 0 {
            let mut carry = 19u64;
            for limb in &mut self.0 {
                let sum = *limb + carry;
                *limb = sum & 0x0007_ffff_ffff_ffff;
                carry = sum >> 51;
            }
        }

        let mut out = [0u8; 32];
        let w0 = self.0[0] | (self.0[1] << 51);
        let w1 = (self.0[1] >> 13) | (self.0[2] << 38);
        let w2 = (self.0[2] >> 26) | (self.0[3] << 25);
        let w3 = (self.0[3] >> 39) | (self.0[4] << 12);

        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out[24..32].copy_from_slice(&w3.to_le_bytes());
        out
    }

    fn add(&self, rhs: &Self) -> Self {
        let mut out = [0u64; 5];
        for i in 0..5 {
            out[i] = self.0[i] + rhs.0[i];
        }
        let mut res = Self(out);
        res.carry();
        res
    }

    fn sub(&self, rhs: &Self) -> Self {
        let bias = [
            0x000f_ffff_ffff_ffda,
            0x000f_ffff_ffff_fffe,
            0x000f_ffff_ffff_fffe,
            0x000f_ffff_ffff_fffe,
            0x000f_ffff_ffff_fffe,
        ];
        let mut out = [0u64; 5];
        for i in 0..5 {
            out[i] = (self.0[i] + bias[i]) - rhs.0[i];
        }
        let mut res = Self(out);
        res.carry();
        res
    }

    fn mul(&self, rhs: &Self) -> Self {
        let a = self.0;
        let b = rhs.0;
        let mut c = [0u128; 5];
        for i in 0..5 {
            for j in 0..5 {
                let prod = u128::from(a[i]) * u128::from(b[j]);
                if i + j < 5 {
                    c[i + j] += prod;
                } else {
                    c[i + j - 5] += 19 * prod;
                }
            }
        }

        let mask = 0x0007_ffff_ffff_ffffu128;
        let mut out = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..5 {
            let sum = c[i] + carry;
            out[i] = (sum & mask) as u64;
            carry = sum >> 51;
        }
        let sum0 = u128::from(out[0]) + carry * 19;
        out[0] = (sum0 & mask) as u64;
        carry = sum0 >> 51;
        for limb in out.iter_mut().skip(1) {
            let sum = u128::from(*limb) + carry;
            *limb = (sum & mask) as u64;
            carry = sum >> 51;
        }
        out[0] += (carry * 19) as u64;
        Self(out)
    }

    fn square(&self) -> Self {
        self.mul(self)
    }

    fn invert(&self) -> Self {
        // Exponent is p - 2 = 2^255 - 21 (0x7fff...ffeb)
        let p_minus_2: [u8; 32] = [
            0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];

        let mut res = Self::ONE;
        for bit_idx in (0..255).rev() {
            res = res.square();
            let bit = (p_minus_2[bit_idx / 8] >> (bit_idx % 8)) & 1;
            if bit == 1 {
                res = res.mul(self);
            }
        }
        res
    }

    fn cswap(swap: u64, a: &mut Self, b: &mut Self) {
        let mask = !(swap.wrapping_sub(1));
        for i in 0..5 {
            let dummy = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= dummy;
            b.0[i] ^= dummy;
        }
    }
}

/// Performs RFC 7748 X25519 scalar multiplication.
#[must_use]
pub fn x25519(scalar: &[u8; 32], point_u: &[u8; 32]) -> [u8; 32] {
    let mut scalar_k = *scalar;
    scalar_k[0] &= 0xf8;
    scalar_k[31] &= 127;
    scalar_k[31] |= 64;

    let x_1 = Fe::from_bytes(point_u);
    let mut x_2 = Fe::ONE;
    let mut z_2 = Fe::ZERO;
    let mut x_3 = x_1;
    let mut z_3 = Fe::ONE;
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let k_t = u64::from((scalar_k[t / 8] >> (t % 8)) & 1);
        swap ^= k_t;
        Fe::cswap(swap, &mut x_2, &mut x_3);
        Fe::cswap(swap, &mut z_2, &mut z_3);
        swap = k_t;

        let sum_a = x_2.add(&z_2);
        let sq_aa = sum_a.square();
        let diff_b = x_2.sub(&z_2);
        let sq_bb = diff_b.square();
        let diff_e = sq_aa.sub(&sq_bb);
        let sum_c = x_3.add(&z_3);
        let diff_d = x_3.sub(&z_3);
        let prod_da = diff_d.mul(&sum_a);
        let prod_cb = sum_c.mul(&diff_b);

        x_3 = prod_da.add(&prod_cb).square();
        z_3 = x_1.mul(&prod_da.sub(&prod_cb).square());
        x_2 = sq_aa.mul(&sq_bb);
        z_2 = diff_e.mul(&sq_aa.add(&Fe::A24.mul(&diff_e)));
    }

    Fe::cswap(swap, &mut x_2, &mut x_3);
    Fe::cswap(swap, &mut z_2, &mut z_3);

    let result = x_2.mul(&z_2.invert());
    result.to_bytes()
}

/// Computes X25519 public key from private scalar using standard base point 9.
#[must_use]
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    x25519(scalar, &BASE_POINT)
}
