use tfhe::integer::{ClientKey, ServerKey, RadixCiphertext};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
use crate::{KeyExpansion::KeyExpansion};


fn main() {
    let key_bytes: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c,
    ];

    let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    let sk = ServerKey::new_radix_server_key(&ck);
   

}
