# Shared rules

`rules.json` is the single source of truth for the description patterns and risky parameter names. All three scanners use it:

| Scanner | How it loads the rules |
|---|---|
| Python (`checks/scan.py`) | Reads the file at import time |
| Rust (`rust/`) | Embeds it at compile time with `include_str!` |
| Worker (`worker/`) | Imports it as a JSON module, and Wrangler inlines it into the bundle |

## Format

```json
{
  "version": 1,
  "description_rules": [
    { "type": "steering_language", "severity": "high", "patterns": ["ignore previous", "..."] }
  ],
  "risky_parameter_names": ["url", "..."]
}
```

- Each pattern is a regular expression, matched **case-insensitively** anywhere in the tool description. A rule reports one finding per pattern that matches.
- Patterns must behave the same in Python `re`, Rust `regex` and JavaScript `RegExp`. Stick to the common subset: literals, `.`, `*`, `+`, `?`, `[...]`, `\s`, `(?:...)`, `$`. Lookarounds, backreferences and inline flags are not portable.
- `risky_parameter_names` lists the string parameters that `unconstrained_risky_parameter` flags when they have no `enum` or `pattern`. Python and the Worker use it; Rust has no schema check.

Checks that are not simple patterns stay in their own implementation: encoded content, zero-width characters and the non-ASCII ratio (Python only), and `description_too_long` (Worker only).

## Parity corpus

`parity-cases.json` lists descriptions and, written by hand, the finding types every scanner must report for each one. The Python, Rust and Worker test suites all run it, so a change to `rules.json`, or a bug in a single scanner, fails CI.

## Adding or changing a pattern

1. Edit `rules.json`.
2. Add a case to `parity-cases.json` that the new pattern alone triggers, plus a near-miss that must stay clean if the pattern could over-match.
3. Run all three suites:

   ```bash
   (cd checks && python3 -m unittest test_scan.py -v)
   (cd rust && cargo test --locked)
   node --test worker/test/index.test.mjs
   ```

4. Update [checks/rules.md](../checks/rules.md) if the rule's meaning changed.
