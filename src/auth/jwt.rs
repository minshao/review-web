use super::{store::token_exists_in_store, AuthError};
use crate::Store;
use anyhow::anyhow;
use async_graphql::Result;
use chrono::{Duration, NaiveDateTime};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use review_database as database;
use serde::{Deserialize, Serialize};
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

lazy_static::lazy_static! {
    static ref JWT_EXPIRES_IN: Arc<RwLock<i64>> = Arc::new(RwLock::new(3600));
    static ref JWT_SECRET: Arc<RwLock<Vec<u8>>> = Arc::new(RwLock::new(vec![]));
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: i64,
}

impl Claims {
    fn new(sub: String, role: String, exp: i64) -> Self {
        Self { sub, role, exp }
    }
}

pub fn create_token(username: String, role: String) -> Result<(String, NaiveDateTime), AuthError> {
    let expires_in = JWT_EXPIRES_IN
        .read()
        .map_err(|e| AuthError::ReadJwtSecret(e.to_string()))?;
    let exp = chrono::Utc::now() + Duration::seconds(*expires_in);

    let claims = Claims::new(username, role, exp.timestamp());
    let jwt_secret = JWT_SECRET
        .read()
        .map_err(|e| AuthError::ReadJwtSecret(e.to_string()))?;

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&jwt_secret),
    )?;
    let expiration_time = NaiveDateTime::new(exp.date_naive(), exp.time());

    Ok((token, expiration_time))
}

pub fn decode_token(token: &str) -> anyhow::Result<Claims> {
    let jwt_secret = JWT_SECRET
        .read()
        .map_err(|e| AuthError::ReadJwtSecret(e.to_string()))?;
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&jwt_secret),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

pub fn update_jwt_expires_in(new_expires_in: i64) -> anyhow::Result<()> {
    JWT_EXPIRES_IN
        .write()
        .map(|mut expires_in| {
            *expires_in = new_expires_in;
        })
        .map_err(|e| anyhow!("jwt_expires_in: {}", e))
}

pub fn update_jwt_secret(new_secret: Vec<u8>) -> anyhow::Result<()> {
    JWT_SECRET
        .write()
        .map(|mut secret| {
            *secret = new_secret;
        })
        .map_err(|e| anyhow!("jwt_secret: {}", e))
}

pub fn validate_token(
    store: &Arc<Store>,
    token: &str,
) -> Result<(String, database::Role), AuthError> {
    let jwt_secret = JWT_SECRET
        .read()
        .map_err(|e| AuthError::ReadJwtSecret(e.to_string()))?;
    let decoded_token = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&jwt_secret),
        &Validation::default(),
    )?;

    if token_exists_in_store(store, token, &decoded_token.claims.sub)? {
        let role = database::Role::from_str(&decoded_token.claims.role)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        Ok((decoded_token.claims.sub, role))
    } else {
        Err(AuthError::InvalidToken(
            "Token not found in the database".into(),
        ))
    }
}
