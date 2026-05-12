# markdownlint Configuration

## 2026-05-12: Created `.markdownlint.yaml`

### What was done
Created `/home/dev/pvthfhe/.markdownlint.yaml` with 10 disabled rules to relax the markdown linter to match the project's existing doc style.

### Disabled rules and their meanings
| Rule | Meaning | Why disabled |
|------|---------|-------------|
| MD013 | Line length limit | Long lines in tables/code blocks are common in project docs |
| MD033 | No inline HTML | Project README uses inline HTML (e.g., `<br>` tags) |
| MD041 | First line should be top-level heading | Some doc files start with subheadings |
| MD024 | No duplicate headings | Design docs reuse heading names across sections |
| MD026 | Trailing punctuation in headings | Some headings end with punctuation |
| MD029 | Ordered list item prefix | Non-sequential numbering used in some docs |
| MD036 | Emphasis used as heading | Bold text used as pseudo-headings |
| MD040 | Fenced code blocks must have language | Some code blocks lack language tags |
| MD046 | Code block style consistency | Mix of indented and fenced code blocks |
| MD047 | End files with single newline | Project files may use different newline conventions |

### File location
`/home/dev/pvthfhe/.markdownlint.yaml` (repo root)

### Verification
- YAML syntax validated with Python's `yaml.safe_load` — valid
- All 10 rules present (10 lines, one per rule)
