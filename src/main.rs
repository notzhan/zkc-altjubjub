use halo2_proofs::arithmetic::BaseExt;
use lazy_static::lazy_static;
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use halo2_proofs::pairing::bn256::Fr;
use std::str::FromStr;
use ff::Field;
use num_traits::identities::Zero;
use sha2::{Digest, Sha256};
use rand::prelude::*;

pub fn bn_to_field<F: BaseExt>(bn: &BigUint) -> F {
    let mut bytes = bn.to_bytes_le();
    bytes.resize(48, 0);
    let mut bytes = &bytes[..];
    F::read(&mut bytes).unwrap()
}

pub fn field_to_bn<F: BaseExt>(f: &F) -> BigUint {
    let mut bytes: Vec<u8> = Vec::new();
    f.write(&mut bytes).unwrap();
    BigUint::from_bytes_le(&bytes[..])
}

lazy_static! {
    static ref D_BIG: BigUint = BigUint::parse_bytes(
        b"12181644023421730124874158521699555681764249180949974110617291017600649128846",
        10
        )
        .unwrap();
    static ref D: Fr = bn_to_field(&(D_BIG));
    static ref A_BIG: BigUint = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495616",
        10
        )
        .unwrap();
    static ref A: Fr = bn_to_field(&(A_BIG));
    pub static ref Q: BigUint = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10
        )
        .unwrap();
    static ref B8: Point = Point {
        //x: bn_to_field(&(BigUint::from_str("21237458262955047976410108958495203094252581401952870797780751629344472264183").unwrap())),
        x: bn_to_field(&(BigUint::parse_bytes(b"2ef3f9b423a2c8c74e9803958f6c320e854a1c1c06cd5cc8fd221dc052d76df7", 16).unwrap())),
        y: bn_to_field(&(BigUint::from_str("2544379904535866821506503524998632645451772693132171985463128613946158519479").unwrap())),
    };
}

pub struct PointProjective {
    pub x: Fr,
    pub y: Fr,
}

impl PointProjective {
    pub fn affine(&self) -> Point {
        let x = self.x;
        let y = self.y;
        Point { x, y }
    }

    pub fn add(&self, q: &PointProjective) -> PointProjective {
        // add-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
        let u1 = &self.x;
        let v1 = &self.y;
        let u2 = &q.x;
        let v2 = &q.y;
        // u3 = (u1 * v2 + v1 * u2) / (1 + D * u1 * u2 * v1 * v2)
        let u3_m = u1.mul(&v2).add(&v1.mul(&u2));
        let u3_d = D.mul(&u1).mul(&u2).mul(&v1).mul(&v2).add(&Field::one());
        let u3 = u3_m.mul(&u3_d.invert().unwrap());

        // v3 = (v1 * v2 - A * u1 * u2) / (1 - D * u1 * u2 * v1 * v2)
        let v3_m = v1.mul(&v2).sub(&A.mul(&u1).mul(&u2));
        let v3_d = D.mul(&u1).mul(&u2).mul(&v1).mul(&v2).sub(&Field::one());
        let v3 = v3_m.mul(&v3_d.neg().invert().unwrap());
        PointProjective {
            x: u3,
            y: v3,
        }
    }
}

pub struct Point {
    pub x: Fr,
    pub y: Fr,
}

impl Point {
    pub fn identity() -> Self {
        Point {
            x: Fr::zero(),
            y: Fr::one(),
        }
    }

    pub fn new(x: Fr, y: Fr) -> Self {
        Point { x, y }
    }

    pub fn projective(&self) -> PointProjective {
        PointProjective {
            x: self.x,
            y: self.y,
        }
    }

    pub fn add(&self, other: &Point) -> Point {
        self.projective().add(&other.projective()).affine()
    }

    pub fn mul_scalar(&self, n: &BigUint) -> Point {
        let mut r = Point::identity().projective();
        let mut exp = self.projective();


        let mut t = n.clone();
        while t != BigUint::zero() {
            if t.clone() % 2u8 == BigUint::from(1u8) {
                r = r.add(&exp);
            }
            exp = exp.add(&exp);
            t = t >> 1;
        }
        r.affine()
    }
}

pub struct PrivateKey {
    pub key: BigUint,
}

pub struct Signature {
    pub r_b8: Point,
    pub s: BigUint,
}

impl PrivateKey {
    pub fn import(b: BigUint) -> PrivateKey {
        let sk: BigUint = b;
        PrivateKey { key: sk }
    }

    pub fn public(&self) -> Point {
        B8.mul_scalar(&self.key)
    }
    pub fn sign(&self, msg: BigUint) -> Result<Signature, String> {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let r = BigUint::from_bytes_be(&bytes);
        let r_b8 = B8.mul_scalar(&r);

        // message hash TODO
        let h = BigUint::parse_bytes(b"5f65e638d535ae8f273bb4d01c5b0c853131e1c7b5f142a95299677a147fba0", 16).unwrap();
        println!("h is {:?}", h);

        let s1 = self.key.clone();
        let h2 = h * s1;
        let q = BigUint::parse_bytes(b"2736030358979909402780800718157159386076813972158567259200215660948447373041", 10).unwrap();

        let h3 = if &h2 >= &q {
            &h2 % &q
        } else {
            h2.clone()
        };
        let s = r + h3;

        Ok(Signature { r_b8: r_b8, s })
    }
}

pub fn new_key() -> PrivateKey {
    let mut rng = rand::thread_rng();
    let sk_raw = rng.gen_biguint(512);
    PrivateKey::import(sk_raw)
}

fn generate_test_commands(num_commands: usize) -> Vec<BigUint> {
    (0..num_commands).map(|i| i.to_biguint().unwrap()).collect()
}

fn field_to_bytes_pack(field: &Fr) -> String {
    let mut hex_str = String::from("0x");
    for value in BigUint::to_u64_digits(&field_to_bn(field)) {
        let bytes = value.to_le_bytes();
        let hex_chunk = hex::encode(&bytes);
        hex_str.push_str(&hex_chunk);
    }
    hex_str.push_str(":bytes-packed");
    hex_str
}

fn bn_to_bytes_pack(bn: &BigUint) -> String {
    let mut hex_str = String::from("0x");
    for value in BigUint::to_u64_digits(&bn) {
        let bytes = value.to_le_bytes();
        let hex_chunk = hex::encode(&bytes);
        hex_str.push_str(&hex_chunk);
    }
    hex_str.push_str(":bytes-packed");
    hex_str
}

fn main() {
    let commands = generate_test_commands(1);
    println!("commands: {:?}", commands);

    let mut hasher = Sha256::new();
    let command: u64 = 0;

    println!("command: {:?}", command);

    hasher.update(command.to_le_bytes());

    let msghash = hasher.finalize();
    println!("msghash: {:?}", msghash);

    let sk = new_key();
    println!("private key: {:?}", sk.key);

    let pk = sk.public();

    println!("public x : {:?}, {:?} ", BigUint::to_u64_digits(&field_to_bn(&pk.x)), field_to_bn(&pk.x));
    println!("public y : {:?}, {:?} ", BigUint::to_u64_digits(&field_to_bn(&pk.y)), field_to_bn(&pk.y));
    println!("public x : {}", field_to_bytes_pack(&pk.x));
    println!("public y : {}", field_to_bytes_pack(&pk.y));

    // TODO generate message
    let msg_biguint = BigUint::parse_bytes(b"46231925624a5cc96571e7e58f7cd1351ea1d668e88453fccd2571923378c41", 16).unwrap();
    println!("msghash is {:?}", BigUint::to_u64_digits(&msg_biguint));

    let sig = sk.sign(msg_biguint).unwrap();

    println!("sig r x is: {:?} {:?}", BigUint::to_u64_digits(&field_to_bn(&sig.r_b8.x)), field_to_bn(&sig.r_b8.x));
    println!("sig r y is: {:?} {:?}", BigUint::to_u64_digits(&field_to_bn(&sig.r_b8.y)), field_to_bn(&sig.r_b8.y));
    println!("sig s is {:?}, {:?}", BigUint::to_u64_digits(&sig.s), sig.s);

    println!("sig r x : {}", field_to_bytes_pack(&sig.r_b8.x));
    println!("sig r y : {}", field_to_bytes_pack(&sig.r_b8.y));
    println!("sig s : {}", bn_to_bytes_pack(&sig.s));
}
