use base64;
use hex;

fn hex_to_64(hex: &String) -> String {
    let raw = hex::decode(hex);
    let txt = raw.unwrap();
    println!("{}", String::from_utf8_lossy(&*txt));
    base64::encode(&txt)
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
    let hex = String::from("1c0111001f010100061a024b53535009181c");
    let bytes = String::from("686974207468652062756c6c277320657965");
    let result = xor_hex(&hex, &bytes);
    assert_eq!(result, "746865206b696420646f6e277420706c6179")
}

fn single_byte_xor(str: &[u8], b: u8) -> Vec<u8> {
    let result: Vec<u8> = str.iter().map(|x| x ^ b).collect();
    result
}

//adapted from https://crypto.stackexchange.com/a/30259
fn score_plain_english(str: &[u8]) -> f64 {
    let freq = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
        0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
        0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
    ];
    let mut count = vec![0; 26];
    let mut ignored = 0;
    for byte in str {
        if byte >= &65u8 && byte <= &90u8 {
            count[*byte as usize - 65] += 1;
        } else if byte >= &97u8 && byte <= &122u8 {
            count[*byte as usize - 97] += 1;
        } else if byte >= &32u8 && byte <= &126u8 {
            ignored += 1
        } else if byte == &9u8 || byte == &10u8 || byte == &13u8 {
            ignored += 1
        } else {
            return std::f64::MAX;
        }
    }
    let mut score = 0.0;
    let len = str.len() - ignored;
    for i in 0..26 {
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
    println!("{}",String::from_utf8_lossy(&message));
}

