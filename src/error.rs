
#[derive(Debug)]
pub enum ErrorKind {
    TooShort,
    TypeNotFound,
    BadRequestType,
    InvalidData,
    KeyNotFound,
    KeyNotCreated,
    Signature,
}

use std::fmt;
use std::str::Utf8Error;

impl From<Utf8Error> for ErrorKind {
    fn from(_: Utf8Error) -> ErrorKind {
        ErrorKind::InvalidData
    }
}

impl From<signature::Error> for ErrorKind {
    fn from(_:signature::Error) -> ErrorKind {
        ErrorKind::Signature
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ErrorKind::TooShort => write!(fmt, "Data is too short"),
            ErrorKind::TypeNotFound => write!(fmt, "Type no found"),
            ErrorKind::InvalidData => write!(fmt, "Invalid data"),
            ErrorKind::KeyNotFound => write!(fmt, "Key not found"),
            ErrorKind::BadRequestType => write!(fmt, "Bad request type"),
            ErrorKind::KeyNotCreated => write!(fmt, "Bad request type"),
            ErrorKind::Signature => write!(fmt, "Signature error"),
        }
    }
}

pub type Result<T> = std::result::Result<T, ErrorKind>;
