pub mod mysql;
pub mod postgres;
pub mod sqlite;

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_rows: u64,
    pub max_cell_bytes: u64,
    pub max_response_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct QueryOutput {
    pub result_sets: Vec<ResultSet>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_affected: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_insert_id: Option<i64>,

    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[async_trait::async_trait]
pub trait Driver: Send + Sync {
    fn name(&self) -> &'static str;

    fn introspection_hint(&self) -> &'static str;

    fn exec_notes(&self) -> &'static str;

    fn enforces_read_only_at_connection(&self) -> bool {
        false
    }

    async fn assert_read_only(&self) -> Result<()>;

    async fn exec(&self, sql: &str, limits: Limits) -> Result<QueryOutput>;
}

pub(crate) fn cap_cell(value: serde_json::Value, max_cell_bytes: u64) -> serde_json::Value {
    let serde_json::Value::String(s) = &value else {
        return value;
    };
    if max_cell_bytes == 0 || s.len() as u64 <= max_cell_bytes {
        return value;
    }
    let total = s.len();
    let mut end = max_cell_bytes as usize;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    serde_json::Value::String(format!(
        "{}\u{2026}[truncated; {total} bytes total]",
        &s[..end]
    ))
}

pub(crate) fn estimate_bytes(value: &serde_json::Value) -> u64 {
    use serde_json::Value as J;
    let len = match value {
        J::Null => 4,
        J::Bool(_) => 5,
        J::Number(n) => n.to_string().len(),
        J::String(s) => s.len() + 2,

        J::Array(_) | J::Object(_) => 16,
    };
    len as u64 + 1
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub(crate) fn float_to_json(f: f64) -> serde_json::Value {
    serde_json::Number::from_f64(f)
        .map(serde_json::Value::Number)
        .unwrap_or_else(|| serde_json::Value::String(f.to_string()))
}

#[cfg(test)]
mod tests {
    use super::cap_cell;

    #[test]
    fn cap_cell_truncates_at_char_boundary_and_marks() {
        let long = format!("{}\u{00E9} tail", "x".repeat(9));
        let capped = cap_cell(serde_json::Value::String(long.clone()), 10);
        let serde_json::Value::String(s) = capped else {
            panic!("expected string");
        };

        assert!(
            s.starts_with("xxxxxxxxx\u{2026}[truncated; 16 bytes total]"),
            "{s}"
        );

        let v = serde_json::Value::String("short".into());
        assert_eq!(cap_cell(v.clone(), 10), v);
        let big = serde_json::Value::String("y".repeat(100));
        assert_eq!(cap_cell(big.clone(), 0), big);
    }
}
