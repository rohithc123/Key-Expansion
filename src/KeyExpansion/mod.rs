use std::array;
//TODO need to import the sub_byte and other functions 
// use crate::{sub_byte, TFheRoundKey, AES_SBOX};
use rayon::prelude::*;
use tfhe::integer::{ServerKey, RadixCiphertext};
use tfhe::MatchValues;

#[derive(Clone)]
struct FheWord([RadixCiphertext; 4]);

fn to_fhe_words(bytes: [RadixCiphertext; 16]) -> [FheWord; 4] {
    let mut iter = bytes.into_iter();
    array::from_fn(|_| {
        FheWord(array::from_fn(|_| iter.next().unwrap()))
    })
}

fn from_fhe_words(words: [FheWord; 4]) -> [RadixCiphertext; 16] {
    let mut iter = words
        .into_iter()
        .flat_map(|w| w.0.into_iter());

    array::from_fn(|_| iter.next().unwrap())
}

impl FheWord {
    fn rot_word(&self) -> Self {
        let mut arr = self.0.clone();
        arr.rotate_left(1);
        Self(arr)
    }

    fn sub_word(&self, s_box_xor_rcon: [u8; 256], sk: &ServerKey) -> Self {
        let new_bytes: [RadixCiphertext; 4] = self.0
            .par_iter()
            .enumerate()
            .map(|(i, enc_byte)| {
                if i == 0 {
                    let vec: Vec<(u8, u8)> = (0..256)
                        .map(|i| (i as u8, s_box_xor_rcon[i]))
                        .collect();

                    sk.match_value_parallelized(enc_byte, &MatchValues::new(vec).unwrap()).0
                } else {
                    sub_byte(sk, enc_byte)
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("Expected exactly 4 elements");
        Self(new_bytes)
    }

    fn bitxor(&self, other: &Self, sk: &ServerKey) -> Self {
        let new_bytes: [RadixCiphertext; 4] = self.0
            .par_iter()
            .zip(other.0.par_iter())
            .map(|(a, b)| sk.bitxor_parallelized(a, b))
            .collect::<Vec<_>>()
            .try_into()
            .expect("Expected exactly 4 elements");
        Self(new_bytes)
    }
}

const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

pub fn fhe_key_expansion(sk: &ServerKey, initial_key: [RadixCiphertext; 16]) -> [FheRoundKey; 11] {
    let mut words: Vec<FheWord> = Vec::with_capacity(44);
    words.extend_from_slice(&to_fhe_words(initial_key));

    for i in 4..44 {
        let mut temp = words[i - 1].clone();
        // Every 4th word: apply the key schedule core.
        if i % 4 == 0 {
            temp = temp.rot_word();

            let s_box_xor_rcon = AES_SBOX.map(|byte| byte ^ RCON[i / 4]);
            temp = temp.sub_word(s_box_xor_rcon, sk);
        }
        let new_word = words[i - 4].bitxor(&temp, sk);

        words.push(new_word);
    }

    let mut iter = words.into_iter();
    array::from_fn(|_| {
        let round_words: [FheWord; 4] =
            array::from_fn(|_| iter.next().expect("Missing word"));

        FheRoundKey(from_fhe_words(round_words))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::integer::ClientKey;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;
    use crate::{decrypt_block, encrypt_block};
    const EXPECTED_ROUND_KEYS: [[u8; 16]; 11] = [
        [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
        [0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05],
        [0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f],
        [0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b],
        [0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00],
        [0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc],
        [0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd],
        [0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f],
        [0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f],
        [0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e],
        [0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6],
    ];

    #[test]
    fn test_fhe_key_expansion() {
        let key_bytes: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];

        let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
        let sk = ServerKey::new_radix_server_key(&ck);

        let enc_key = encrypt_block(&ck, &key_bytes);
        let enc_round_keys = fhe_key_expansion(&sk, enc_key);

        let round_keys = enc_round_keys.map(|round_key| decrypt_block(&ck, &round_key.0));
        assert_eq!(
            round_keys,
            EXPECTED_ROUND_KEYS,
            "TFHE key expansion did not produce the expected round keys"
        );
    }
}