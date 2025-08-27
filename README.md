# Quantum Saferunner

Saferunner1 is a Wasmtime-based CLI that executes WebAssembly plugins with layered safety: policy manifests, integrity verification, static vulnerability scanning, telemetry, disassembly, opcode feature extraction, and rule-based classification. It ships with Docker hardening and a CI workflow.

## Table of contents
- Quickstart
- Usage
- Command-line options
- Policy manifest
- Static vulnerability scanning
- Telemetry and artifacts
- Disassembly and opcode analysis
- Docker and Compose
- GitHub Actions CI
- Security considerations
- Persistent storage (design)
- Web UI roadmap (design)
- Troubleshooting
- License

## Quickstart

### Prerequisites
- Rust (stable) and Cargo
- Windows, macOS, or Linux
- Optional: Docker and Docker Compose

### Build
```bash
cd "3 webAssembly/saferunner1"
cargo build --release
```
Windows binary:
```
3 webAssembly/saferunner1/target/release/saferunner1.exe
```
Linux/macOS binary:
```
3 webAssembly/saferunner1/target/release/saferunner1
```

## Usage
All commands assume the working directory is `3 webAssembly/saferunner1`.

### 1) Generate SHA-256 for manifest
```bash
cargo run --release -- -f test_plugin.wasm -g
```
Use the printed hash in your manifest under `expected_hash`.

### 2) Classification only (no execution)
```bash
cargo run --release -- -f test_plugin.wasm -c -o out
```
Creates `out/plugin_classification.json` and `out/opcode_vector.json`.

### 3) Static vulnerability scan only
```bash
cargo run --release -- -f test_plugin.wasm --scan-only -o out
```
Creates `out/vuln_report.json`.

### 4) Execute a function
```bash
cargo run --release -- -f test_plugin.wasm -x add -i 5 -o out
```
Signature attempts (in order): `(i32)->i32`, `(i32)->()`, `()->i32`, `()->()`.

Artifacts are written to `out/` (see Telemetry and artifacts).

## Command-line options
```
-f, --file <path>         Path to .wasm file (required)
-x, --func <name>         Exported function to call (optional)
-i, --input <string>      Optional input (tries i32 and no-arg variants)
-g, --generate-hash       Print SHA-256 of the wasm and exit
-c, --classify-only       Perform static classification only
    --scan-only           Perform static vulnerability scan only
-o, --outdir <path>       Output directory (default: current dir)
```

## Policy manifest
Saferunner1 looks for `<file>.manifest.json`. Example:
```json
{
  "name": "Example Plugin",
  "version": "1.0.0",
  "description": "Demo",
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
  "requires_input": false,
  "allowed_input_types": ["i32"],
  "expected_hash": "<sha256>",
  "hash_algorithm": "sha256"
}
```
If missing, a restrictive default manifest is applied.

## Static vulnerability scanning
- Extracts opcode frequencies and entropy
- Flags suspicious patterns (crypto ops, obfuscation-like control flow, memory-heavy behavior)
- Heuristically inspects imports for potentially dangerous capabilities (e.g., WASI fs/network)
- Produces `vuln_report.json` with `severity`, `score`, and `findings`

This is a lightweight rule-based scan intended for defense-in-depth.

## Telemetry and artifacts
With `-o out`, all artifacts are written to the specified directory:
- `execution_log.json`: success, error, function, input/output, duration
- `telemetry_<plugin>.json`: event stream (load, integrity, policy, traps, perf, classification)
- `opcode_vector.json`: opcode frequency vector
- `plugin_classification.json`: classifier result
- `vuln_report.json`: static vulnerability report

## Disassembly and opcode analysis
After execution or classification, the runner prints section info and operators, and writes opcode statistics to `out/opcode_vector.json`.

## Docker and Compose
Build an image (multi-stage, distroless final):
```bash
docker build -t saferunner1:latest "3 webAssembly/saferunner1"
```
Run with Compose (read-only project mount, resource limits):
```bash
docker compose -f "3 webAssembly/saferunner1/docker-compose.yml" up --build
```
This mounts the project at `/work:ro` and writes artifacts to `./out`.

## GitHub Actions CI
Workflow: `.github/workflows/saferunner-ci.yml`
- Builds the project
- Runs classification-only on a sample
- Uploads artifacts

## Security considerations
- Policy validation blocks disallowed functions/inputs
- Integrity verification blocks tampered plugins
- Static scanning raises risk indicators pre-execution
- Container hardening: non-root, read-only root fs, no-new-privileges, dropped caps
- Apply CPU/memory/PIDs limits; add a job timeout watchdog around execution

Wasmtime provides strong isolation; pair it with OS/container defenses.

## Persistent storage (design)
See `docs/storage_design.md` for the per-user sandbox layout, quotas, and cleanup strategy.

## Web UI roadmap (design)
See `docs/webui_plan.md` for an interactive editor with real-time output via SSE/WebSockets, job routing, and artifact browsing.

## Troubleshooting
- Use a recent stable Rust toolchain
- On Windows, avoid paths with special characters if you hit escaping issues
- Verify the `.wasm` file is readable and valid
- Ensure `expected_hash` matches the generated hash when integrity checks fail

## License
MIT or Apache-2.0 (choose and update accordingly)
