use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::{crypto, error::AppError};

const MIN_TOKEN_LENGTH: usize = 3;
const MAX_EXACT_TOKEN_LENGTH: usize = 16;
const HMAC_CONTEXT: &str = "network-auth-card-search-v1\n";

pub fn card_token_hashes(card_key: &str, system_key: &str) -> Result<Vec<String>, AppError> {
    let normalized_card_key = normalize(card_key);
    let card_key_length = normalized_card_key.len();
    if card_key_length < MIN_TOKEN_LENGTH {
        return Ok(Vec::new());
    }

    let max_token_length = MAX_EXACT_TOKEN_LENGTH.min(card_key_length);
    let mut tokens = HashSet::new();
    for token_length in MIN_TOKEN_LENGTH..=max_token_length {
        for offset in 0..=card_key_length - token_length {
            tokens.insert(normalized_card_key[offset..offset + token_length].to_string());
        }
    }
    hash_tokens(tokens.into_iter(), system_key)
}

pub fn keyword_token_hashes(keyword: &str, system_key: &str) -> Result<Vec<String>, AppError> {
    let normalized_keyword = normalize(keyword);
    let keyword_length = normalized_keyword.len();
    if keyword_length < MIN_TOKEN_LENGTH {
        return Ok(Vec::new());
    }
    if keyword_length <= MAX_EXACT_TOKEN_LENGTH {
        return hash_tokens([normalized_keyword].into_iter(), system_key);
    }

    let mut tokens = HashSet::new();
    for offset in 0..=keyword_length - MAX_EXACT_TOKEN_LENGTH {
        tokens.insert(normalized_keyword[offset..offset + MAX_EXACT_TOKEN_LENGTH].to_string());
    }
    hash_tokens(tokens.into_iter(), system_key)
}

pub(crate) fn normalize(value: &str) -> String {
    value
        .trim()
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_uppercase() as char)
        .collect()
}

fn hash_tokens<I>(tokens: I, system_key: &str) -> Result<Vec<String>, AppError>
where
    I: Iterator<Item = String>,
{
    let hmac_key = Sha256::digest(system_key.as_bytes());
    let mut token_hashes = tokens
        .map(|token| {
            crypto::hmac_sha256_hex_string(hmac_key.as_slice(), &format!("{HMAC_CONTEXT}{token}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    token_hashes.sort();
    token_hashes.dedup();
    Ok(token_hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_php_compatible_card_search_hashes() {
        let system_key = "test-system-key";

        assert_eq!(
            vec!["a3d7e98942f342f3a827b2bb452bdb442e93110c2b6e2a12cf0031a3d59f42c2"],
            keyword_token_hashes("abc", system_key).expect("keyword token")
        );
        assert_eq!(
            vec![
                "78c43cd22f08cd19312f754f563a4f54071af6ea110c4cb5dd63c3f173f25732",
                "7f09f58b91d8fefaeea81937e79e17ee0bffcdac03201a4ae370ebef38312047",
                "a3d7e98942f342f3a827b2bb452bdb442e93110c2b6e2a12cf0031a3d59f42c2"
            ],
            card_token_hashes("AB-CD", system_key).expect("card tokens")
        );
        assert_eq!(
            vec![
                "76a26bb38904a9b32163d77908a31d56a7b02ec9a413823371cf72a900a0bf0f",
                "bd6c29f83143df202a3b16b331fddb9a820fa6a247b9be704282b15d369cb8a0"
            ],
            keyword_token_hashes("ABCDEFGHIJKLMNOPQ", system_key).expect("long keyword")
        );
    }

    #[test]
    fn normalizes_like_php_card_search_index() {
        assert_eq!("ABC123", normalize(" ab-c_123 "));
        assert!(
            card_token_hashes("ab", "system-key")
                .expect("short card")
                .is_empty()
        );
    }
}
