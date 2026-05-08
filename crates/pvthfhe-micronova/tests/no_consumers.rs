use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cargo_metadata_json() -> String {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .current_dir(repo_root())
        .output()
        .unwrap_or_else(|error| panic!("failed to run cargo metadata: {error}"));

    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("cargo metadata output was not valid UTF-8")
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    fn parse(mut self) -> JsonValue {
        let value = self.parse_value();
        self.skip_ws();
        assert_eq!(self.pos, self.bytes.len(), "trailing JSON input");
        value
    }

    fn parse_value(&mut self) -> JsonValue {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => JsonValue::String(self.parse_string()),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'-' | b'0'..=b'9') => JsonValue::Number(self.parse_number()),
            Some(b't') => {
                self.expect_bytes(b"true");
                JsonValue::Bool(true)
            }
            Some(b'f') => {
                self.expect_bytes(b"false");
                JsonValue::Bool(false)
            }
            Some(b'n') => {
                self.expect_bytes(b"null");
                JsonValue::Null
            }
            other => panic!("unexpected JSON token: {other:?}"),
        }
    }

    fn parse_object(&mut self) -> JsonValue {
        self.expect(b'{');
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return JsonValue::Object(map);
        }

        loop {
            self.skip_ws();
            let key = self.parse_string();
            self.skip_ws();
            self.expect(b':');
            let value = self.parse_value();
            map.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                other => panic!("unexpected object separator: {other:?}"),
            }
        }

        JsonValue::Object(map)
    }

    fn parse_array(&mut self) -> JsonValue {
        self.expect(b'[');
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return JsonValue::Array(items);
        }

        loop {
            items.push(self.parse_value());
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                other => panic!("unexpected array separator: {other:?}"),
            }
        }

        JsonValue::Array(items)
    }

    fn parse_string(&mut self) -> String {
        self.expect(b'"');
        let mut result = String::new();
        while let Some(byte) = self.peek() {
            self.pos += 1;
            match byte {
                b'"' => return result,
                b'\\' => result.push(self.parse_escape()),
                byte => result.push(byte as char),
            }
        }
        panic!("unterminated JSON string");
    }

    fn parse_number(&mut self) -> String {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        String::from_utf8(self.bytes[start..self.pos].to_vec()).expect("invalid UTF-8 in number")
    }

    fn parse_escape(&mut self) -> char {
        let byte = self.next().expect("unterminated escape sequence");
        match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{0008}',
            b'f' => '\u{000c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            other => panic!("unsupported JSON escape: {other:?}"),
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) {
        assert_eq!(self.next(), Some(byte), "expected byte {byte:?}");
    }

    fn expect_bytes(&mut self, expected: &[u8]) {
        for byte in expected {
            self.expect(*byte);
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }
}

fn as_object(value: &JsonValue) -> &BTreeMap<String, JsonValue> {
    match value {
        JsonValue::Object(map) => map,
        other => panic!("expected object, got {other:?}"),
    }
}

fn as_array(value: &JsonValue) -> &[JsonValue] {
    match value {
        JsonValue::Array(items) => items,
        other => panic!("expected array, got {other:?}"),
    }
}

fn as_string(value: &JsonValue) -> &str {
    match value {
        JsonValue::String(text) => text,
        other => panic!("expected string, got {other:?}"),
    }
}

fn read_repo_file(relative_path: &str) -> String {
    let full_path = repo_root().join(relative_path);
    std::fs::read_to_string(&full_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", full_path.display()))
}

fn touch_point_count(doc: &str) -> usize {
    doc.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("- `crates/")
                || trimmed.starts_with("- `Justfile`")
                || trimmed.starts_with("- `SECURITY.md`")
        })
        .count()
}

#[test]
fn micronova_has_no_workspace_dependents_and_migration_stays_bounded() {
    let metadata = Parser::new(&cargo_metadata_json()).parse();
    let root = as_object(&metadata);

    let workspace_members: BTreeSet<String> = as_array(
        root.get("workspace_members")
            .expect("cargo metadata missing workspace_members"),
    )
    .iter()
    .map(|member| as_string(member).to_owned())
    .collect();

    let packages = as_array(
        root.get("packages")
            .expect("cargo metadata missing packages"),
    );
    let resolve = as_object(root.get("resolve").expect("cargo metadata missing resolve"));
    let nodes = as_array(
        resolve
            .get("nodes")
            .expect("cargo metadata missing resolve.nodes"),
    );

    let micronova_id = packages
        .iter()
        .find_map(|package| {
            let package = as_object(package);
            match package.get("name") {
                Some(JsonValue::String(name)) if name == "pvthfhe-micronova" => {
                    match package.get("id") {
                        Some(JsonValue::String(id)) => Some(id.to_owned()),
                        _ => None,
                    }
                }
                _ => None,
            }
        })
        .expect("pvthfhe-micronova package missing from cargo metadata");

    let dependents: Vec<String> = nodes
        .iter()
        .filter_map(|node| {
            let node = as_object(node);
            let node_id = match node.get("id") {
                Some(JsonValue::String(id)) => id.as_str(),
                _ => return None,
            };
            if node_id == micronova_id || !workspace_members.contains(node_id) {
                return None;
            }

            let dependencies = match node.get("dependencies") {
                Some(JsonValue::Array(dependencies)) => dependencies,
                _ => return None,
            };
            let depends_on_micronova = dependencies.iter().any(
                |dependency| matches!(dependency, JsonValue::String(id) if id == &micronova_id),
            );

            depends_on_micronova.then(|| node_id.to_owned())
        })
        .collect();

    assert!(
        dependents.is_empty(),
        "expected no workspace dependents for pvthfhe-micronova"
    );

    let touch_points = touch_point_count(&read_repo_file(".sisyphus/design/sonobe-migration.md"));
    assert!(
        touch_points <= 8,
        "sonobe migration doc must enumerate at most 8 touch points, found {touch_points}"
    );
}
