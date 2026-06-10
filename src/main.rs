use base64::{Engine as _, alphabet::URL_SAFE, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
struct CustomPayload {
    sub: String,
    exp: usize,
}

fn generate_jwt_token(secret: &[u8], sub: String, exp: usize) -> String {
    let token = encode(
        &Header::default(),
        &CustomPayload { sub: sub, exp: exp },
        &EncodingKey::from_secret(secret),
    )
    .unwrap();

    token
}
fn main() {
    // PART#1 A part of generate token & signing the token with secret key
    let secret = b"my_secret_key";
    let token = generate_jwt_token(secret, String::from("nonpawit_silabumrungrad"), 200000000);

    // Output from generate token
    println!("Generated token: {}", token);

    // Seperate to be a part of json web token (jwt)
    println!("Header of token with base64: {:?}", token.split(".").nth(0));
    println!(
        "Payload of token with base64: {:?}",
        token.split(".").nth(1)
    );
    println!("Signature of token: {:?}", token.split(".").nth(2));

    // PART#2 A part of decode token
    // a reason why use algorithm as HS256 because when encode process it use default algorithm
    let parts: Vec<&str> = token.split(".").collect();
    println!(
        "Decoded header of token: {}",
        String::from_utf8(URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap()
    );
    println!(
        "Decoded paload of token: {}",
        String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap()
    );

    // PART#3 A part of verify the token with secret key
    let message_to_sign = format!("{}.{}", parts[0], parts[1]);
    let signature_from_token = parts[2];

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(message_to_sign.as_bytes());
    let generated_signature_bytes = mac.finalize().into_bytes();
    let generated_signature_b64 = URL_SAFE_NO_PAD.encode(generated_signature_bytes);
    println!("Signature from token: {}", signature_from_token);
    println!("Generated signature:   {}", generated_signature_b64);
}
