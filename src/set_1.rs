use base64;
use hex;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};

fn hex_to_64(hex: &String) -> String {
    let v = hex::decode(hex).unwrap();
    println!("{}", String::from_utf8_lossy(&*v));
    base64::encode(&v)
}

#[test]
fn test_chall1() {
    let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let txt = hex_to_64(&hex);
    assert_eq!(
        txt,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )
}

fn xor_hex(hex1: &String, hex2: &String) -> String {
    let v1 = hex::decode(hex1).unwrap();
    let v2 = hex::decode(hex2).unwrap();
    let result: Vec<u8> = v1.iter().zip(v2).map(|(x1, x2)| x1 ^ x2).collect();
    println!("{}", String::from_utf8_lossy(&*result));
    hex::encode(result)
}

#[test]
fn test_chall2() {
    let hex_1 = String::from("1c0111001f010100061a024b53535009181c");
    let hex_2 = String::from("686974207468652062756c6c277320657965");
    let result = xor_hex(&hex_1, &hex_2);
    assert_eq!(result, "746865206b696420646f6e277420706c6179")
}

fn single_byte_xor(str: &[u8], b: u8) -> Vec<u8> {
    let result: Vec<u8> = str.iter().map(|x| x ^ b).collect();
    result
}

//adapted from https://crypto.stackexchange.com/a/30259
fn score_plain_english(str: &[u8]) -> f64 {
    //Frequencies letters + space as the 27th element
    let freq = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
        0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
        0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.1918182,
    ];
    let mut count = vec![0; 27];
    let mut ignored = 0;
    for byte in str {
        if byte >= &65u8 && byte <= &90u8 {
            count[*byte as usize - 65] += 1;
        } else if byte >= &97u8 && byte <= &122u8 {
            count[*byte as usize - 97] += 1;
        //Here we also score the space (ascii code 32)
        } else if byte == &32u8 {
            count[26] += 1
        } else if byte >= &33u8 && byte <= &126u8 {
            ignored += 1
        } else if byte == &9u8 || byte == &10u8 || byte == &13u8 {
            ignored += 1
        } else {
            return std::f64::MAX;
        }
    }
    let mut score = 0.0;
    let len = str.len() - ignored;
    for i in 0..freq.len() {
        let observed: f64 = count[i] as f64;
        let expected: f64 = len as f64 * freq[i];
        let difference = observed - expected;
        score += difference * difference / expected;
    }
    score
}

fn break_single_byte_xor(hex: &String) -> Vec<u8> {
    let mut score: f64 = std::f64::MAX;
    let mut message: Vec<u8> = vec![0u8];
    let s = hex::decode(hex).unwrap();
    for byte in 0..=255 {
        let xored_s = single_byte_xor(&s, byte);
        let output_score = score_plain_english(&xored_s);
        if output_score < score {
            score = output_score;
            message = xored_s;
        }
    }
    message
}

#[test]
fn test_chall3() {
    let hex = String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let message = break_single_byte_xor(&hex);
    println!("{}", String::from_utf8_lossy(&message));
}

fn seek_single_byte_xored_in_file(path: &String) -> Vec<u8> {
    let mut score: f64 = std::f64::MAX;
    let mut message: Vec<u8> = vec![0u8];
    let file = File::open(path).unwrap();
    for line in BufReader::new(file).lines() {
        let line_message = break_single_byte_xor(&line.unwrap());
        if line_message != vec![0u8] {
            let output_score = score_plain_english(&line_message);
            println!("message found : {}", String::from_utf8_lossy(&line_message));
            println!("score : {}", &output_score);
            if output_score < score {
                score = output_score;
                message = line_message;
            }
        }
    }
    message
}

/* Little comment on this one
    The final message is not the good one, this is most likely due to my choice of method for scoring the plaintext and the fact that message is very short
    I Have printed all the messages and their respective scores in the function tho so you can see for yourself
    The message is : "Now that the party is jumping"
*/
#[test]
fn test_chall4() {
    let path = String::from("./data/4.txt");
    let message = seek_single_byte_xored_in_file(&path);
    println!(
        "most likely to be plain english message {}",
        String::from_utf8_lossy(&message)
    );
}

fn encrypt_repeating_key_xor(message: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut cipher = vec![0u8; message.len()];
    let mut i = 0;
    for b in message.iter() {
        cipher[i] = b ^ key[i % key.len()];
        i += 1
    }
    cipher
}

#[test]
fn test_chall5() {
    let plain_message =
        String::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
            .into_bytes();
    let key = String::from("ICE").into_bytes();
    let cipher_message = encrypt_repeating_key_xor(&plain_message, &key);
    assert_eq!(hex::encode(cipher_message), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
}

fn hamming_distance(v1: &[u8], v2: &[u8]) -> i32 {
    if v1.len() != v2.len() {
        return -1;
    }
    let mut diff = 0;
    for (x1, x2) in v1.iter().zip(v2) {
        for j in 0..8 {
            let mask = 1 << j;
            if (x1 & mask) != (x2 & mask) {
                diff += 1
            }
        }
    }
    diff
}

#[test]
fn test_hamming_distance_chall6() {
    let v1 = String::from("this is a test");
    let v2 = String::from("wokka wokka!!!");
    let distance = hamming_distance(v1.as_bytes(), v2.as_bytes());
    assert_eq!(distance, 37);
}

fn break_repeating_key_xor(path: &String) -> Vec<u8> {
    let f = File::open(path).expect("Unable to open");
    let mut cipher_b64 = Vec::new();
    BufReader::new(f).read_to_end(&mut cipher_b64).unwrap();
    let cipher = base64::decode(&cipher_b64).unwrap();
    let key_size = find_key_size(&cipher, 40);
    println!("found keysize {}", key_size);
    let key = find_repeating_key_xor_key(&cipher, key_size);
    println!("found key {}", String::from_utf8_lossy(&key));
    let plain_message = encrypt_repeating_key_xor(&cipher, &key);
    plain_message
}

fn find_key_size(cipher: &Vec<u8>, max: usize) -> i32 {
    let mut min_distance = std::f64::MAX;
    let mut key = 0;
    for i in 2..max {
        let distance =
            hamming_distance(&cipher[0..i * 15], &cipher[i * 15..i * 2 * 15]) as f64 / i as f64;
        if distance < min_distance {
            key = i;
            min_distance = distance;
        }
    }
    key as i32
}

fn find_single_byte_xor_key(v: &Vec<u8>) -> u8 {
    let mut score: f64 = std::f64::MAX;
    let mut key = 0u8;
    for byte in 0..255 {
        let xored_s = single_byte_xor(v, byte);
        let output_score = score_plain_english(&xored_s);
        if output_score < score {
            score = output_score;
            key = byte;
        }
    }
    key
}

fn find_repeating_key_xor_key(cipher: &Vec<u8>, key_size: i32) -> Vec<u8> {
    let mut key = vec![0u8; key_size as usize];
    for i in 0..key_size as usize {
        let mut block = Vec::new();
        for j in (i..cipher.len()).step_by(key_size as usize) {
            block.push(cipher[j])
        }
        key[i] = find_single_byte_xor_key(&block);
    }
    key
}

#[test]
fn test_chall6() {
    let path = String::from("./data/6.txt");
    let message = break_repeating_key_xor(&path);
    println!("{}", String::from_utf8_lossy(&message));
}
