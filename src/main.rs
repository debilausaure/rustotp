use hex;
use hmac::{Hmac, Mac, NewMac};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha1::Sha1;
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // get a 30 second timestamp
    let timestamp : u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30;
    println!{"Timestamp      : {}", timestamp};

    // creating a key

    let mut rng = ChaCha20Rng::from_entropy();
    let mut random_key = [0u8; 20];
    rng.fill(&mut random_key);
    println!("20 bytes key   : {}", hex::encode(random_key));

    //let mut key_bytes = [0u8; 20];
    //let key_str = "3132333435363738393031323334353637383930";
    //hex::decode_to_slice(&key_str, &mut key_bytes).unwrap();
    //println!("Hardcoded key  : {}", hex::encode(&key_bytes));

    // getting the MAC
    type HmacSha1 = Hmac<Sha1>;
    let mut hmac_sha1 = HmacSha1::new_varkey(&random_key).unwrap();
    //let mut hmac_sha1 = HmacSha1::new_varkey(&key_bytes).unwrap();
    hmac_sha1.update(&timestamp.to_be_bytes());
    let msg_auth_code: [u8; 20] = hmac_sha1.finalize().into_bytes().try_into().unwrap();
    println!("Hmac-sha1      : {}", hex::encode(msg_auth_code));

    // retrieving dynamic offset of slice
    let dyn_offset: usize = (msg_auth_code.last().unwrap() & 0xf).into();
    println!("Dynamic offset : {}", dyn_offset);

    //retrieving the corresponding 4 bytes slice
    let slice = &msg_auth_code[dyn_offset..dyn_offset + 4];
    println!("Selected slice : {}", hex::encode(slice));

    //casting into an u32
    let decimal = u32::from_be_bytes(slice.try_into().unwrap()) & 0x7fffffff;
    println!("Decimal        : {:08}", decimal);

    let hotp = decimal % 1000000;
    println! {"TOTP           : {}", hotp};
}
