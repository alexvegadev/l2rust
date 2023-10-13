use crate::blowfish::blowfish::Cipher;

pub fn checksum(raw: &mut Vec<u8>) -> bool {
    let mut chksum: i32 = 0;
    let count = raw.len() - 8;
    let mut i = 0;

    while i < count {
        let mut ecx: i32 = i32::from(raw[i]);
        ecx |= i32::from(raw[i + 1]) << 8;
        ecx |= i32::from(raw[i + 2]) << 16;
        ecx |= i32::from(raw[i + 3]) << 24;
        chksum ^= ecx;
        i += 4;
    }

    let mut ecx: i32 = i32::from(raw[i]);
    ecx |= i32::from(raw[i + 1]) << 8;
    ecx |= i32::from(raw[i + 2]) << 16;
    ecx |= i32::from(raw[i + 3]) << 24;

    raw[i] = (chksum & 0xFF) as u8;
    raw[i + 1] = ((chksum >> 8) & 0xFF) as u8;
    raw[i + 2] = ((chksum >> 16) & 0xFF) as u8;
    raw[i + 3] = ((chksum >> 24) & 0xFF) as u8;

    ecx == chksum
}

pub fn blowfish_decrypt(mut encrypted: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, String> {
    match Cipher::new(key) {
        Ok(cipher) => {
            if encrypted.len()%8 != 0 {
                return Err("encrypted data length is not a multiple of the block size".to_string());
            }

            let count = encrypted.len() / 8;

            let mut decrypted = vec![0u8; encrypted.len()];

            for i in 0..count {
                let dest = &mut decrypted[i * 8..(i + 1) * 8];
                cipher.decrypt(&mut encrypted[i * 8..(i + 1) * 8], dest);
            }
            let result: Result<Vec<u8>, String> = Ok(decrypted);
            return result;
        },
        Err(e) => {
            return Err(e);
        }
    }
}