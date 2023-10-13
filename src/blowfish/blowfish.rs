use std::fmt::format;

use super::fixed;


const BLOCK_SIZE: usize = 8;

pub struct Cipher {
    p: [u32; 18],
    s0: [u32; 256],
    s1: [u32; 256],
    s2: [u32; 256],
    s3: [u32; 256],
}

impl Cipher {
    pub fn new(key: Vec<u8>) -> Result<Cipher, String> {
        let mut result: Cipher = Cipher {
            p: [0; 18],
            s0: [0; 256],
            s1: [0; 256],
            s2: [0; 256],
            s3: [0; 256],
        };
        let len = key.len();
        if len < 1 || len > 56 {
            return Err(format(format_args!("crypto/blowfish: invalid key size : {}", len)));
        }
        init_cipher(&mut result);
        expand_key(key, &mut result);
        Ok(result)
    }

    pub fn new_salt(mut key: &mut Vec<u8>, mut salt: &mut Vec<u8>) -> Result<Cipher, String> {
        if salt.len() == 0 {
            return Cipher::new(key.to_vec());
        }
        let mut result: Cipher = Cipher {
            p: [0; 18],
            s0: [0; 256],
            s1: [0; 256],
            s2: [0; 256],
            s3: [0; 256],
        };
        let len = key.len();
        if len < 1 || len > 56 {
            return Err(format(format_args!("crypto/blowfish: invalid key size : {}", len)));
        }
        init_cipher(&mut result);
        expand_key_with_salt(&mut result, &mut key, &mut salt);
        Ok(result)
    }

    pub fn block_size(self) -> usize {
        BLOCK_SIZE
    }

    pub fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        let l = (u32::from(src[3]) << 24) | (u32::from(src[2]) << 16) | (u32::from(src[1]) << 8) | u32::from(src[0]);
        let r = (u32::from(src[7]) << 24) | (u32::from(src[6]) << 16) | (u32::from(src[5]) << 8) | u32::from(src[4]);

        let (new_l, new_r) = encrypt_block(l, r, self);

        dst[0] = (new_l >> 24) as u8;
        dst[1] = (new_l >> 16) as u8;
        dst[2] = (new_l >> 8) as u8;
        dst[3] = new_l as u8;

        dst[4] = (new_r >> 24) as u8;
        dst[5] = (new_r >> 16) as u8;
        dst[6] = (new_r >> 8) as u8;
        dst[7] = new_r as u8;
    }

    pub fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        let l = (u32::from(src[3]) << 24) | (u32::from(src[2]) << 16) | (u32::from(src[1]) << 8) | u32::from(src[0]);
        let r = (u32::from(src[7]) << 24) | (u32::from(src[6]) << 16) | (u32::from(src[5]) << 8) | u32::from(src[4]);

        let (new_l, new_r) = decrypt_block(l, r, self);

        dst[0] = (new_l >> 24) as u8;
        dst[1] = (new_l >> 16) as u8;
        dst[2] = (new_l >> 8) as u8;
        dst[3] = new_l as u8;

        dst[4] = (new_r >> 24) as u8;
        dst[5] = (new_r >> 16) as u8;
        dst[6] = (new_r >> 8) as u8;
        dst[7] = new_r as u8;
    }
}

fn init_cipher(c: &mut Cipher) {
    c.p.copy_from_slice(&fixed::P);
    c.s0.copy_from_slice(&fixed::S0);
    c.s1.copy_from_slice(&fixed::S1);
    c.s2.copy_from_slice(&fixed::S2);
    c.s3.copy_from_slice(&fixed::S3);
}

fn get_next_word(b: &mut [u8], pos: &mut usize) -> u32 {
    let mut w: u32 = 0;
    let mut j = *pos;
    
    for _ in 0..4 {
        w = (w << 8) | u32::from(b[j]);
        j += 1;
        
        if j >= b.len() {
            j = 0;
        }
    }
    
    *pos = j;
    w
}

fn expand_key(key: Vec<u8>, c: &mut Cipher) {
    let mut j = 0;
    for i in 0..18 {
        let mut d: u32 = 0;
        for _ in 0..4 {
            d = (d << 8) | u32::from(key[j]);
            j += 1;
            if j >= key.len() {
                j = 0;
            }
        }
        c.p[i] ^= d;
    }

    let mut l: u32 = 0;
    let mut r: u32 = 0;

    for i in (0..18).step_by(2) {
        let (new_l, new_r) = encrypt_block(l, r, c);
        c.p[i] = new_l;
        c.p[i + 1] = new_r;
        l = new_l;
        r = new_r;
    }

    for i in 0..256 {
        let (new_l, new_r) = encrypt_block(l, r, c);
        c.s0[i] = new_l;
        c.s0[i + 1] = new_r;
        l = new_l;
        r = new_r;
    }

    for i in 0..256 {
        let (new_l, new_r) = encrypt_block(l, r, c);
        c.s1[i] = new_l;
        c.s1[i + 1] = new_r;
        l = new_l;
        r = new_r;
    }

    for i in 0..256 {
        let (new_l, new_r) = encrypt_block(l, r, c);
        c.s2[i] = new_l;
        c.s2[i + 1] = new_r;
        l = new_l;
        r = new_r;
    }

    for i in 0..256 {
        let (new_l, new_r) = encrypt_block(l, r, c);
        c.s3[i] = new_l;
        c.s3[i + 1] = new_r;
        l = new_l;
        r = new_r;
    }
}

pub fn expand_key_with_salt(c: &mut Cipher, key: &mut Vec<u8>, salt: &mut Vec<u8>) {
    let mut j = 0;
    for i in 0..18 {
        c.p[i] ^= get_next_word(key, &mut j);
    }

    j = 0;
    let mut l = 0u32;
    let mut r = 0u32;

    for i in (0..18).step_by(2) {
        l ^= get_next_word(salt, &mut j);
        r ^= get_next_word(salt, &mut j);
        let (new_l, new_r) = encrypt_block(l, r, c);
        c.p[i] = new_l;
        c.p[i + 1] = new_r;
        l = new_l;
        r = new_r;
    }

    for i in (0..256).step_by(2) {
        l ^= get_next_word(salt, &mut j);
        r ^= get_next_word(salt, &mut j);
        let (new_l, new_r) = encrypt_block(l, r, c);
        c.s0[i] = new_l;
        c.s0[i + 1] = new_r;
        l = new_l;
        r = new_r;
    }

    for i in (0..256).step_by(2) {
        l ^= get_next_word(salt, &mut j);
        r ^= get_next_word(salt, &mut j);
        let (new_l, new_r) = encrypt_block(l, r, c);
        c.s1[i] = new_l;
        c.s1[i + 1] = new_r;
        l = new_l;
        r = new_r;
    }

    for i in (0..256).step_by(2) {
        l ^= get_next_word(salt, &mut j);
        r ^= get_next_word(salt, &mut j);
        let (new_l, new_r) = encrypt_block(l, r, c);
        c.s2[i] = new_l;
        c.s2[i + 1] = new_r;
        l = new_l;
        r = new_r;
    }

    for i in (0..256).step_by(2) {
        l ^= get_next_word(salt, &mut j);
        r ^= get_next_word(salt, &mut j);
        let (new_l, new_r) = encrypt_block(l, r, c);
        c.s3[i] = new_l;
        c.s3[i + 1] = new_r;
        l = new_l;
        r = new_r;
    }
}

fn encrypt_block(l: u32, r: u32, c: &Cipher) -> (u32, u32) {
    let mut xl = l;
    let mut xr = r;

    xl ^= c.p[0];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[1];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[2];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[3];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[4];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[5];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[6];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[7];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[8];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[9];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[10];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[11];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[12];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[13];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[14];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[15];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[16];
    xr ^= c.p[17];

    (xr, xl)
}

fn decrypt_block(l: u32, r: u32, c: &Cipher) -> (u32, u32) {
    let mut xl = l;
    let mut xr = r;

    xl ^= c.p[17];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[16];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[15];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[14];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[13];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[12];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[11];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[10];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[9];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[8];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[7];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[6];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[5];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[4];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[3];
    xr ^= ((c.s0[(xl >> 24) as usize] + c.s1[(xl >> 16) as usize]) ^ c.s2[(xl >> 8) as usize]) + c.s3[(xl) as usize] ^ c.p[2];
    xl ^= ((c.s0[(xr >> 24) as usize] + c.s1[(xr >> 16) as usize]) ^ c.s2[(xr >> 8) as usize]) + c.s3[(xr) as usize] ^ c.p[1];
    xr ^= c.p[0];

    (xr, xl)
}