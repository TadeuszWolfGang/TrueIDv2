//! Shared pagination request/response models.

use serde::{Deserialize, Serialize};

/// Generic pagination query parameters.
///
/// Parameters: `page` - optional page number starting from 1, `limit` - optional page size.
/// Returns: deserialized pagination object.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct PaginationParams {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

impl PaginationParams {
    /// Resolves normalized page number.
    ///
    /// Parameters: none.
    /// Returns: page number in range `[1, u32::MAX]`.
    pub fn page_or(self, default: u32) -> u32 {
        self.page.unwrap_or(default).max(1)
    }

    /// Resolves normalized limit with upper bound.
    ///
    /// Parameters: `default` - fallback limit, `max` - max allowed page size.
    /// Returns: clamped page size.
    pub fn limit_or(self, default: u32, max: u32) -> u32 {
        self.limit.unwrap_or(default).clamp(1, max.max(1))
    }

    /// Computes SQL offset from page and limit.
    ///
    /// Parameters: `default` - fallback limit, `max` - max limit clamp.
    /// Returns: offset suitable for SQL `LIMIT/OFFSET`.
    pub fn offset(self, default: u32, max: u32) -> i64 {
        let page = self.page_or(1);
        let limit = self.limit_or(default, max);
        i64::from((page - 1) * limit)
    }
}

/// Generic paginated API response.
///
/// Parameters: generic `T` is payload item type.
/// Returns: serialized page wrapper with metadata.
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub total: i64,
    pub page: u32,
    pub limit: u32,
    pub total_pages: u32,
}

impl<T: Serialize> PaginatedResponse<T> {
    /// Builds a paginated response and computes `total_pages`.
    ///
    /// Parameters: `data` - page rows, `total` - total row count, `page` - current page, `limit` - page size.
    /// Returns: normalized paginated response object.
    pub fn new(data: Vec<T>, total: i64, page: u32, limit: u32) -> Self {
        let safe_limit = limit.max(1);
        let total_pages = if total <= 0 {
            0
        } else {
            ((total as f64) / f64::from(safe_limit)).ceil() as u32
        };
        Self {
            data,
            total,
            page,
            limit: safe_limit,
            total_pages,
        }
    }
}
