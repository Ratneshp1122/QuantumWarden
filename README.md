# QuantumWarden

[![Rust CI](https://github.com/Ratneshp1122/QuantumWarden/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/Ratneshp1122/QuantumWarden/actions/workflows/rust-ci.yml)

QuantumWarden is a Rust research prototype for inspecting and executing WebAssembly modules with Wasmtime. It combines integrity checks, manifest-based execution policy, static opcode and import analysis, rule-based risk classification, and structured JSON telemetry.

> Status: research prototype. It is useful for experimenting with WebAssembly security controls, but it is not a production sandbox.

## What it currently does

- Loads and executes WebAssembly modules through Wasmtime.
- Verifies module integrity against an optional SHA-256 hash in a manifest.
- Restricts execution to manifest-approved exported functions and validates numeric input ranges.
- Extracts opcode frequencies and calculates an entropy score.
- Flags suspicious opcode patterns and potentially dangerous WASI, filesystem, or socket imports.
- Produces rule-based classifications: Safe, Suspicious, Malicious, or Unknown.
- Records execution results, policy violations, traps, performance data, integrity checks, and classification events as JSON.
- Supports analysis-only and scan-only modes that do not execute the target module.
- Compiles and runs tests on every push and pull request through GitHub Actions.

## Security model

QuantumWarden currently provides three pre-execution gates:

1. Static scan of opcodes and imports.
2. SHA-256 integrity verification when an expected hash is supplied.
3. Manifest validation for the requested function and input range.

The classifier is heuristic and rule-based. It is not a trained machine-learning model, and a Safe result must not be interpreted as proof that a module is harmless.

## Build

Requirements:

- Stable Rust toolchain
- Cargo

```bash
git clone https://github.com/Ratneshp1122/QuantumWarden.git
cd QuantumWarden
cargo build --release
```

The binary is created at:

```text
target/release/saferunner1
```

On Windows, the filename is `saferunner1.exe`.

## Usage

Generate a SHA-256 hash for a module:

```bash
cargo run --release -- --file test_plugin.wasm --generate-hash
```

Run classification without executing the module:

```bash
cargo run --release -- --file test_plugin.wasm --classify-only --outdir out
```

Run the static scan without executing the module:

```bash
cargo run --release -- --file test_plugin.wasm --scan-only --outdir out
```

Execute an exported function:

```bash
cargo run --release -- --file test_plugin.wasm --func add --input 5 --outdir out
```

Supported function signatures are currently limited to:

- `(i32) -> i32`
- `(i32) -> ()`
- `() -> i32`
- `() -> ()`

## Policy manifest

QuantumWarden looks for a manifest beside the module using the name `<module>.manifest.json`.

```json
{
  "name": "Example Plugin",
  "version": "1.0.0",
  "description": "Demonstration module",
  "functions": [
    {
      "name": "add",
      "signature": "(i32) -> i32",
      "max_execution_time_ms": 1000,
      "allowed_input_range": [0, 100]
    }
  ],
  "memory_limit": 10,
  "fuel_limit": 1000,
  "trust_level": "Low",
  "requires_input": true,
  "allowed_input_types": ["i32"],
  "expected_hash": "<sha256>",
  "hash_algorithm": "sha256"
}
```

The current implementation enforces the function allowlist, input range, and expected hash. The memory, fuel, maximum-execution-time, trust-level, and allowed-input-type fields are represented in the schema but are not all enforced yet.

## Output artifacts

When `--outdir out` is supplied, QuantumWarden may create:

| File | Contents |
|---|---|
| `execution_log.json` | Function, input/output, duration, integrity result, policy violations, and error state |
| `telemetry_<module>.json` | Structured security and execution events |
| `opcode_vector.json` | Opcode frequency map |
| `plugin_classification.json` | Rule-based classification, confidence, and risk factors |
| `vuln_report.json` | Static findings, severity, score, entropy, and suspicious imports |

Generated JSON files included in this repository are small examples from local test modules.

## Repository layout

```text
.
|-- Cargo.toml
|-- src/
|   `-- main.rs
|-- .github/workflows/
|   `-- rust-ci.yml
|-- *.wasm
|-- *.wat
|-- *.manifest.json
`-- example JSON artifacts
```

## Current limitations

- The classifier uses fixed heuristics rather than a trained or calibrated model.
- Manifest memory and fuel limits are not fully enforced by the current execution path.
- Wall-clock execution deadlines are not enforced.
- Only a small set of function signatures is supported.
- The runtime does not provide a WASI linker, so modules requiring imported capabilities may fail to instantiate.
- Static opcode patterns can produce both false positives and false negatives.
- The repository needs dedicated unit, integration, adversarial, and resource-exhaustion tests.

## Planned hardening

- Enforce Wasmtime fuel and memory limits.
- Add wall-clock interruption with epoch deadlines.
- Move classification before all executable paths.
- Add adversarial fixtures for infinite loops, memory growth, suspicious imports, tampering, and malformed manifests.
- Separate the CLI into testable modules.
- Add benchmark results for analysis time and execution overhead.

## Why this project exists

The project explores a practical question: how much useful policy and telemetry can a lightweight host add around untrusted WebAssembly plugins before execution? The current implementation is a foundation for answering that question, not a claim that the sandboxing problem is solved.
