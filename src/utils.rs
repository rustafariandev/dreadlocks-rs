pub fn strip_zero(n: &[u8]) -> &[u8] {
    if n.is_empty() || n[0] != 0 {
        n
    } else {
        &n[1..]
    }
}

pub fn add_zero(n: Vec<u8>) -> Vec<u8> {
    if n.is_empty() || n[0] <= 127 {
        n
    } else {
        let zero = &[0_u8];
        let mut n = n.clone();
        n.splice(0..0, zero.iter().cloned());
        n
    }
}

pub fn append_parts(parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().map(|e| e.len() + 4).sum::<usize>();
    let mut data: Vec<u8> = Vec::with_capacity(len);
    for part in parts {
        add_u32_to_vec(&mut data, part.len() as u32);
        data.extend_from_slice(part);
    }
    data
}

pub fn add_u32_to_vec(vec: &mut Vec<u8>, num: u32) {
    vec.push(((num & 0xFF000000) >> 24) as u8);
    vec.push(((num & 0x00FF0000) >> 16) as u8);
    vec.push(((num & 0x0000FF00) >> 8) as u8);
    vec.push((num & 0x000000FF) as u8);
}
