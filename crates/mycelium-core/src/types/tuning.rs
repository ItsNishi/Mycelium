/// Kernel tunable types.

/// A tunable kernel parameter (e.g. sysctl).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TunableParam {
	pub key: String,
	pub value: TunableValue,
	pub description: Option<String>,
}

/// The value of a kernel tunable.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TunableValue {
	String(String),
	Integer(i64),
	Boolean(bool),
}

impl std::fmt::Display for TunableValue {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::String(s) => write!(f, "{s}"),
			Self::Integer(n) => write!(f, "{n}"),
			Self::Boolean(b) => write!(f, "{}", if *b { "1" } else { "0" }),
		}
	}
}
