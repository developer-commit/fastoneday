use thiserror::Error;

use super::{ClassifiedError, ErrorCode};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DriverError {
    #[error("driver name must be a plain .sys filename: `{value}`")]
    InvalidName { value: String },
}

impl ClassifiedError for DriverError {
    fn code(&self) -> ErrorCode {
        ErrorCode::InvalidInput
    }
}
