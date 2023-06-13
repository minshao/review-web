use super::AuthError;
use crate::Store;
use anyhow::{anyhow, bail, Result};
use bincode::Options;
use std::collections::HashSet;

/// Inserts a token into the store.
///
/// # Errors
///
/// Returns an error if the tokens in the store are invalid, if the token cannot be serialized, or
/// if the store cannot be accessed.
pub fn insert_token(store: &Store, token: &str, username: &str) -> Result<()> {
    let map = store.access_token_map();
    let tokens = map.get(username.as_bytes())?;
    let value = if let Some(tokens) = tokens {
        let mut tokens =
            bincode::DefaultOptions::new().deserialize::<HashSet<String>>(tokens.as_ref())?;
        tokens.insert(token.to_string());
        tokens
    } else {
        HashSet::from([token.to_string()])
    };
    let value = bincode::DefaultOptions::new().serialize(&value)?;
    map.put(username.as_bytes(), &value)?;

    Ok(())
}

/// Revokes a token from the store.
///
/// # Errors
///
/// Returns an error if the tokens in the store are invalid, if the token cannot be serialized, or
/// if the store cannot be accessed.
pub fn revoke_token(store: &Store, token: &str) -> Result<()> {
    let decoded_token = super::decode_token(token)?;
    let username = decoded_token.sub;

    let map = store.access_token_map();
    let value = map
        .get(username.as_bytes())?
        .ok_or_else(|| anyhow!("The given token does not exist"))?;
    let mut tokens =
        bincode::DefaultOptions::new().deserialize::<HashSet<String>>(value.as_ref())?;
    if tokens.contains(token) {
        tokens.remove(token);
        let value = bincode::DefaultOptions::new().serialize(&tokens)?;
        map.put(username.as_bytes(), &value)?;
        Ok(())
    } else {
        bail!("The given token does not exist");
    }
}

pub(super) fn token_exists_in_store(
    store: &Store,
    token: &str,
    username: &str,
) -> Result<bool, AuthError> {
    let value = store
        .access_token_map()
        .get(username.as_bytes())
        .map_err(|_| AuthError::InvalidToken("Token not found in the database".into()))?;
    if let Some(value) = value {
        let tokens = bincode::DefaultOptions::new()
            .deserialize::<HashSet<String>>(value.as_ref())
            .map_err(|e| AuthError::Other(format!("An unexpected value in the database: {e}")))?;
        Ok(tokens.contains(token))
    } else {
        Ok(false)
    }
}
