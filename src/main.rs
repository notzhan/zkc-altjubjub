use zkwasm_host_circuits::host::jubjub::Point;
use zkwasm_host_circuits::utils::{ bn_to_field, field_to_bn};
use lazy_static::lazy_static;
use num_bigint::{BigUint, RandBigInt, ToBigInt};
use halo2_proofs::pairing::bn256::Fr;
use std::str::FromStr;
use blake_hash::Digest;

lazy_static! {
    static ref B8: Point = Point {
        x: bn_to_field(&(BigUint::parse_bytes(b"2ef3f9b423a2c8c74e9803958f6c320e854a1c1c06cd5cc8fd221dc052d76df7", 16).unwrap())),
        y: bn_to_field(&(BigUint::parse_bytes(b"05a01167ea785d3f784224644a68e4067532c815f5f6d57d984b5c0e9c6c94b7", 16).unwrap())),
    };
}

pub struct PrivateKey {
    pub key: [u8; 32],
}

fn blh(b: &[u8]) -> Vec<u8> {
    let hash = blake_hash::Blake512::digest(b);
    hash.to_vec()
}

pub struct Signature {
    pub r_b8: Point,
    pub s: BigUint,
}

impl PrivateKey {
    pub fn import(b: Vec<u8>) -> Result<PrivateKey, String> {
        if b.len() != 32 {
            return Err(String::from("imported key can not be bigger than 32 bytes"));
        }
        let mut sk: [u8; 32] = [0; 32];
        sk.copy_from_slice(&b[..32]);
        Ok(PrivateKey { key: sk })
    }

    pub fn scalar_key(&self) -> BigUint {
        let hash: Vec<u8> = blh(&self.key);
        let mut h: Vec<u8> = hash[..32].to_vec();

        h[0] &= 0xF8;
        h[31] &= 0x7F;
        h[31] |= 0x40;

        let sk = BigUint::from_bytes_le(&h[..]);
        sk
    }

    pub fn public(&self) -> Point {
        B8.mul_scalar(&self.scalar_key())
    }

    pub fn sign(&self, msg: BigUint) -> Result<Signature, String> {
        let ax = self.public().x;

        let mut rng = rand::thread_rng();
        let r = rng.gen_biguint(64);
        let r_b8 = B8.mul_scalar(&r);

        let msg_fr: Fr = bn_to_field(&msg);

        let mut content: Vec<u8> = Vec::new();
        content.extend(field_to_bn(&r_b8.x).to_bytes_be());
        content.extend(field_to_bn(&ax).to_bytes_be());
        content.extend(field_to_bn(&msg_fr).to_bytes_be());

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hasher.finalize();

        let mut s = self.scalar_key();
        let h = BigUint::from_bytes_le(&hash);
        s = h * s;
        s = r + s;

        Ok(Signature { r_b8: r_b8, s })
    }
}

pub fn new_key() -> PrivateKey {
    // https://tools.ietf.org/html/rfc8032#section-5.1.5
    let mut rng = rand::thread_rng();
    let sk_raw = rng.gen_biguint(512).to_bigint().unwrap();
    let (_, sk_raw_bytes) = sk_raw.to_bytes_be();
    PrivateKey::import(sk_raw_bytes[..32].to_vec()).unwrap()
}

fn main() {
    let sk = new_key();
    let pk = sk.public();
    println!("public x : {:?}", BigUint::to_u64_digits(&field_to_bn(&pk.x)));
    println!("public y : {:?}", BigUint::to_u64_digits(&field_to_bn(&pk.y)));

    let msg = "123456";
    let c = BigUint::from_str(msg).unwrap();
    println!("msghash is {:?}", BigUint::to_u64_digits(&c));
    let sig = sk.sign(c.clone()).unwrap();

    println!(
        "sig r x is: {:?} {:?}",
        BigUint::to_u64_digits(&field_to_bn(&sig.r_b8.x)),
        field_to_bn(&sig.r_b8.x)
        );
    println!(
        "sig r y is: {:?} {:?}",
        BigUint::to_u64_digits(&field_to_bn(&sig.r_b8.y)),
        field_to_bn(&sig.r_b8.y)
        );

    println!("sig s is {:?}, {:?}", BigUint::to_u64_digits(&sig.s), sig.s);

    let lhs = pk.mul_scalar(&c);
    println!("first round {:?}", lhs);
    let lhs = lhs.add(&sig.r_b8);
    println!("second round {:?}", lhs);
    let base_x = BigUint::parse_bytes(
        b"017054bebd8ed76270b84220f215264ea2e9cc2c72ec13c846bfd7d39d28920a",
        16,
        )
        .unwrap();
    let base_y = BigUint::parse_bytes(
        b"05a01167ea785d3f784224644a68e4067532c815f5f6d57d984b5c0e9c6c94b7",
        16,
        )
        .unwrap();
    let p_g_neg = Point {
        x: bn_to_field(&(base_x)),
        y: bn_to_field(&(base_y)),
    };
    let rhs = p_g_neg.mul_scalar(&sig.s);
    let rst = lhs.add(&rhs);
    println!("third round {:?}", rst);
}
