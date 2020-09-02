use hex;
use hmac::{Hmac, Mac, NewMac};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha1::Sha1;
use std::convert::TryInto;

fn main() {
    // getting a counter
    let counter: u64 = 0;
    println!{"Counter        : {}", counter};

    // creating a key
    let mut rng = ChaCha20Rng::from_entropy();
    let mut key = [0u8; 20];
    rng.fill(&mut key);
    println!("20 bytes key   : {}", hex::encode(key));

    // getting the MAC
    type HmacSha1 = Hmac<Sha1>;
    let mut hmac_sha1 = HmacSha1::new_varkey(&key).unwrap();
    hmac_sha1.update(&counter.to_be_bytes());
    let msg_auth_code: [u8; 20] = hmac_sha1.finalize().into_bytes().try_into().unwrap();
    println!("Hmac-sha1      : {}", hex::encode(msg_auth_code));

    // retrieving dynamic offset of slice
    let dyn_offset: usize = (msg_auth_code.last().unwrap() & 0xf).into();
    println!("Dynamic offset : {}", dyn_offset);

    //retrieving the corresponding 4 bytes slice
    let slice = &msg_auth_code[dyn_offset..dyn_offset + 4];
    println!("Selected slice : {}", hex::encode(slice));

    //casting into an u32
    let decimal = u32::from_be_bytes(slice.try_into().unwrap());
    println!("Decimal        : {:08}", decimal);

    let hotp = decimal % 1000000;
    println! {"HOTP           : {}", hotp};
}
