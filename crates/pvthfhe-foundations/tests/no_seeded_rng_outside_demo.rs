//! R0.7 enforcement lint: no predictable (seeded) RNG constructions in
//! production code paths. Production crypto must use `OsRng` via
//! `pvthfhe_foundations::rng`; predictable RNG is reserved for demos, benches,
//! tests, fuzz harnesses, and simulator code.
//!
//! Precision rules (so the lint fires on real violations, not legitimate code):
//! - Path allowlist: `/tests/`, `/benches/`, demo/bench/example binaries, the
//!   foundations crate itself (the OsRng façade), `pvthfhe-fuzz` (fuzz
//!   harnesses are deterministic by design), the keygen *simulator* (mock
//!   ceremony driver), and the `per_node`/`per_aggregator` CLI bench binaries
//!   (operator-supplied `--seed`, same category as `bench_`/`demo` binaries).
//! - `#[cfg(test)]` items: unit-test code inside `src/` files is skipped (see
//!   `cfg_test_regions` for the heuristic).
//! - Declarations: `fn from_seed` / `fn seed_from_u64` definitions are API
//!   surface; the lint forbids predictable-RNG *calls*, caught at callsites.
//! - Annotation: a hit line — or the line directly above it — carrying
//!   `// allow-seeded-rng: <reason>` is accepted for construction-required
//!   determinism (e.g. Fiat-Shamir transcript-derived seeds).

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

const FORBIDDEN: &str = r"\bseed_from_u64\b|\bfrom_seed\b|\bStdRng::\w*seed|\bChaCha20Rng::\w*seed|\bChaCha8Rng::\w*seed";

const ANNOTATION: &str = "// allow-seeded-rng:";

fn is_allowlisted(path: &str) -> bool {
    path.contains("/tests/")
        || path.contains("/benches/")
        || path.starts_with("crates/pvthfhe-foundations/")
        // Fuzz harnesses are deterministic by design (seed derived from input).
        || path.starts_with("crates/pvthfhe-fuzz/")
        // KeygenSimulator: deterministic mock keygen-ceremony driver (test infra).
        || path == "crates/pvthfhe-aggregator/src/keygen/simulator.rs"
        // CLI bench binaries with operator-supplied `--seed` (same category as
        // the bench_/demo binaries matched by filename below).
        || (path.starts_with("crates/pvthfhe-cli/src/bin/")
            && (path.ends_with("/per_node.rs") || path.ends_with("/per_aggregator.rs")))
        || path.split('/').next_back().is_some_and(|file| {
            file.starts_with("demo")
                || file.starts_with("worked_example")
                || file.starts_with("bench_")
                || file.starts_with("fhe_baseline")
                || file.starts_with("gen_goldens")
        })
}

fn line_has_annotation(content: &str) -> bool {
    content.contains(ANNOTATION)
}

fn is_comment(content: &str) -> bool {
    content.trim_start().starts_with("//")
}

/// Seeded-RNG *declarations* (e.g. `pub fn from_seed(seed: [u8; 32], ...)`) are
/// API surface, not calls. Call expressions never contain the substring
/// `fn from_seed`, so this cannot hide a real callsite.
fn is_fn_declaration(content: &str) -> bool {
    content.contains("fn from_seed") || content.contains("fn seed_from_u64")
}

/// Lexer state for [`code_skeletons`]. Only exists to make brace counting
/// robust: braces inside comments, string literals, char literals, and raw
/// strings must not move the depth counter.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LexState {
    Code,
    /// Nesting depth of `/* ... */`.
    BlockComment(usize),
    Str,
    Char,
    /// Number of `#` in the opening `r#*"`.
    RawStr(usize),
}

/// Char literal iff a closing quote follows within the literal's span:
/// `'x'` (3 chars) or an escape `'\n'` / `'\u{...}'` (backslash never appears
/// in a lifetime). Anything else (`'a`, `'static`) is a lifetime annotation.
fn looks_like_char_literal(chars: &[char], quote: usize) -> bool {
    match chars.get(quote + 1) {
        Some('\\') => true,
        Some(_) => chars.get(quote + 2) == Some(&'\''),
        None => false,
    }
}

/// Returns, per line, the line with comments and string/char literal contents
/// blanked out, so `{`/`}` counting sees code only. State (block comments,
/// raw strings, strings) may span lines; input is compiled workspace Rust, so
/// literals are assumed to terminate. Heuristic, documented in
/// [`cfg_test_regions`]: a misparse can only extend or shrink a *test*
/// exclusion region, it cannot manufacture an exclusion over production code
/// that contains the forbidden pattern outside any `#[cfg(test)]` item.
fn code_skeletons(file: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut state = LexState::Code;

    for line in file.lines() {
        let chars: Vec<char> = line.chars().collect();
        let mut skeleton = String::with_capacity(line.len());
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            match state {
                LexState::Code => match c {
                    '/' if next == Some('/') => break, // rest of line is a comment
                    '/' if next == Some('*') => {
                        state = LexState::BlockComment(1);
                        i += 1;
                    }
                    '"' => state = LexState::Str,
                    'r' if next == Some('"') || next == Some('#') => {
                        let mut j = i + 1;
                        let mut hashes = 0;
                        while chars.get(j) == Some(&'#') {
                            hashes += 1;
                            j += 1;
                        }
                        if chars.get(j) == Some(&'"') {
                            state = LexState::RawStr(hashes);
                            i = j;
                        } else {
                            skeleton.push(c); // identifier starting with `r`
                        }
                    }
                    '\'' => {
                        if looks_like_char_literal(&chars, i) {
                            state = LexState::Char;
                        } else {
                            skeleton.push(c); // lifetime
                        }
                    }
                    _ => skeleton.push(c),
                },
                LexState::BlockComment(depth) => {
                    if c == '/' && next == Some('*') {
                        state = LexState::BlockComment(depth + 1);
                        i += 1;
                    } else if c == '*' && next == Some('/') {
                        state = if depth == 1 {
                            LexState::Code
                        } else {
                            LexState::BlockComment(depth - 1)
                        };
                        i += 1;
                    }
                }
                LexState::Str => match c {
                    '\\' => i += 1, // escaped char
                    '"' => state = LexState::Code,
                    _ => {}
                },
                LexState::Char => match c {
                    '\\' => i += 1, // escaped char
                    '\'' => state = LexState::Code,
                    _ => {}
                },
                LexState::RawStr(hashes) => {
                    if c == '"' {
                        let mut j = i + 1;
                        let mut n = 0;
                        while chars.get(j) == Some(&'#') {
                            n += 1;
                            j += 1;
                        }
                        if n == hashes {
                            state = LexState::Code;
                            i = j - 1;
                        }
                    }
                }
            }
            i += 1;
        }
        // Char literals cannot span lines in valid Rust; if a misdetection
        // left us in Char at EOL, recover rather than swallow the file.
        if state == LexState::Char {
            state = LexState::Code;
        }
        out.push(skeleton);
    }
    out
}

/// 1-based inclusive line ranges covered by `#[cfg(test)]` items.
///
/// Heuristic (simple depth counter): from a line whose trimmed skeleton starts
/// with `#[cfg(test)]`, scan forward to the first `{` of the attributed item
/// (`mod tests`, test `fn`, test-only `impl` method, ...) and skip until the
/// matching closing brace, counting braces over the comment/string-stripped
/// skeletons from [`code_skeletons`]. If the attributed item has no body (a
/// line ending in `;` before any `{`), only the attribute line is excluded.
fn cfg_test_regions(skeletons: &[String]) -> Vec<(usize, usize)> {
    const MARKER: &str = "#[cfg(test)]";
    let mut regions = Vec::new();
    let mut i = 0;
    while i < skeletons.len() {
        let trimmed = skeletons[i].trim_start();
        if !trimmed.starts_with(MARKER) {
            i += 1;
            continue;
        }
        let start = i;
        let mut j = i;
        let mut depth: i32 = 0;
        let mut opened = false;
        while j < skeletons.len() {
            let scan: &str = if j == i {
                &trimmed[MARKER.len()..]
            } else {
                skeletons[j].as_str()
            };
            for c in scan.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        opened = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if opened && depth <= 0 {
                break;
            }
            if !opened && scan.trim_end().ends_with(';') {
                break; // body-less item (e.g. a declaration)
            }
            j += 1;
        }
        let end = j.min(skeletons.len().saturating_sub(1));
        regions.push((start + 1, end + 1));
        i = end + 1;
    }
    regions
}

/// Per-file scan cache: raw lines (for the line-above annotation check) plus
/// precomputed `#[cfg(test)]` regions.
struct FileScan {
    lines: Vec<String>,
    regions: Vec<(usize, usize)>,
}

fn scan_file(root: &Path, path: &str) -> FileScan {
    let content = std::fs::read_to_string(root.join(path)).unwrap_or_default();
    let regions = cfg_test_regions(&code_skeletons(&content));
    FileScan {
        lines: content.lines().map(str::to_owned).collect(),
        regions,
    }
}

fn workspace_root() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().to_path_buf()
}

#[test]
fn no_seeded_rng_in_production() {
    let root = workspace_root();
    let out = Command::new("rg")
        .args(["-n", "--no-heading", "-t", "rust", FORBIDDEN, "crates/"])
        .current_dir(&root)
        .output()
        .expect("rg must be installed");

    assert!(
        out.status.success() || out.status.code() == Some(1),
        "rg failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut scans: HashMap<String, FileScan> = HashMap::new();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut violations = Vec::new();

    for line in stdout.lines().filter(|line| !line.is_empty()) {
        let mut parts = line.splitn(3, ':');
        let (Some(path), Some(line_no), Some(content)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let Ok(line_no) = line_no.parse::<usize>() else {
            continue;
        };

        if is_allowlisted(path)
            || line_has_annotation(content)
            || is_comment(content)
            || is_fn_declaration(content)
        {
            continue;
        }

        let scan = scans
            .entry(path.to_owned())
            .or_insert_with(|| scan_file(&root, path));

        // The annotation is also honored on the line directly above the hit,
        // so it can sit on its own comment line.
        if line_no >= 2
            && scan
                .lines
                .get(line_no - 2)
                .is_some_and(|above| line_has_annotation(above))
        {
            continue;
        }

        // Unit-test code (`#[cfg(test)]` items) inside src/ files.
        if scan
            .regions
            .iter()
            .any(|&(start, end)| start <= line_no && line_no <= end)
        {
            continue;
        }

        violations.push(format!("{path}:{line_no}: {}", content.trim()));
    }

    if !violations.is_empty() {
        panic!(
            "R0.7 violation: {} production seeded-RNG callsite(s):\n{}\n\nMigrate to OsRng via `pvthfhe_foundations::rng::ProductionRng`, or annotate with `// allow-seeded-rng: <reason>` for construction-required determinism.",
            violations.len(),
            violations.join("\n")
        );
    }
}
