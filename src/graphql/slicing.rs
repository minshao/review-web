use std::{fmt, str::FromStr};

use data_encoding::BASE64;

const MAX_SLICE_LEN: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid cursor")]
    InvalidCursor,
    #[error("The value of first and last must be within 1-100")]
    InvalidLimitValue,
    #[error("Invalid or unsupported combination of pagination arguments")]
    InvalidPaginationArgument,
    #[error("You must provide a `first` or `last` value to properly paginate a connection.")]
    MissingPaginationBoundaries,
}

pub fn decode_cursor<T: FromStr>(cursor: &Option<String>) -> Result<Option<(i32, T)>, Error> {
    match cursor.as_ref() {
        Some(c) => {
            let decoded = String::from_utf8(
                BASE64
                    .decode(c.as_bytes())
                    .map_err(|_| Error::InvalidCursor)?,
            )
            .map_err(|_| Error::InvalidCursor)?;
            let Some((id, value)) = decoded.split_once(':') else {
                return Err(Error::InvalidCursor);
            };
            let id = id.parse().map_err(|_| Error::InvalidCursor)?;
            let value = value.parse::<T>().map_err(|_| Error::InvalidCursor)?;
            Ok(Some((id, value)))
        }
        None => Ok(None),
    }
}

pub fn encode_cursor<T: fmt::Display>(id: i32, value: T) -> String {
    BASE64.encode(format!("{id}:{value}").as_bytes())
}

pub fn limit(first: Option<usize>, last: Option<usize>) -> Result<usize, Error> {
    match (first, last) {
        (Some(_), Some(_)) => Err(Error::InvalidPaginationArgument),
        (None, None) => Err(Error::MissingPaginationBoundaries),
        (Some(len), _) | (_, Some(len)) => {
            if (0..=MAX_SLICE_LEN).contains(&len) {
                Ok(len)
            } else {
                Err(Error::InvalidLimitValue)
            }
        }
    }
}

pub fn page_info<D: serde::de::DeserializeOwned>(
    is_first: bool,
    limit: usize,
    mut rows: Vec<D>,
) -> (Vec<D>, bool, bool) {
    let has_previous = has_previous(is_first, limit, rows.len());
    let has_next = has_next(is_first, limit, rows.len());
    if rows.len() > limit {
        if is_first {
            rows.pop();
        } else {
            rows.remove(0);
        }
    }
    (rows, has_previous, has_next)
}

/// Indicates whether more records exist prior to the slice defined by this
/// `Slicing`, assuming that at least `edge_count` records satisfy the
/// requirements of the `Slicing`.
///
/// This is based on `hasPreviousPage` defined in [GraphQL Cursor
/// Connections Specification][spec].
///
/// [spec]:
/// https://relay.dev/graphql/connections.htm#sec-undefined.PageInfo.Fields
fn has_previous(is_first: bool, len: usize, edge_count: usize) -> bool {
    if is_first {
        false
    } else {
        edge_count > len
    }
}

/// Indicates whether more records exist following the slice defined by this
/// `Slicing`, assuming that at least `edge_count` records satisfy the
/// requirements of the `Slicing`.
///
/// This is based on `hasNextPage` defined in [GraphQL Cursor Connections
/// Specification][spec].
///
/// [spec]:
/// https://relay.dev/graphql/connections.htm#sec-undefined.PageInfo.Fields
fn has_next(is_first: bool, len: usize, edge_count: usize) -> bool {
    if is_first {
        edge_count > len
    } else {
        false
    }
}
