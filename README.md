# Quantum Warden

Quantum Warden is a secure WebAssembly runtime designed for controlled plugin execution. Built in Rust, it enforces strict policy-based execution environments with support for runtime limits, manifest validation, hash verification, opcode vectorization, and AI-based plugin classification.

## Features

* Load and execute `.wasm` plugins via CLI
* Memory and CPU execution constraints (via fuel and limits)
* Manifest-based function permissioning
* SHA-256 hash verification of plugins
* Opcode frequency extraction for vectorization
* Plugin classification using a Python-based ML model
* Execution logging in structured JSON format

## Tech Stack

* Language: Rust, Python
* WASM Runtime: wasmtime
* CLI: clap
* Serialization: serde
* Hashing: sha2
* Logging: chrono, serde\_json
* ML: scikit-learn (Python)

## Installation

### Prerequisites

* Rust (1.70 or newer)
* Python 3.8+
* Python dependencies:

  ```bash
  pip install scikit-learn
  ```

### Build Instructions

```bash
git clone https://github.com/yourname/QuantumWarden.git
cd QuantumWarden
cargo build
```

## Usage

### Running a Plugin

```bash
cargo run -- -f test_plugin.wasm -x run --input 42
```

### Plugin Manifest Format

Each plugin must have an accompanying manifest file named `<plugin>.wasm.manifest.json`. Example:

```json
{
  "plugin_name": "test_plugin",
  "allowed_function": "run",
  "input_type": "i32",
  "output_type": "i32",
  "max_fuel": 100000,
  "max_memory_mb": 64,
  "sha256": "<sha256-hash-of-wasm-file>"
}
```

### Logging Output

Each execution generates a JSON log file with:

* Plugin name and hash
* Function invoked
* Input/output
* Execution time
* Timestamp
* ML classification

### Classification (Python)

To classify a plugin, prepare a `training_data.json` and run:

```bash
python classify.py
```

This classifies the opcode vector extracted from the plugin using a pre-trained ML model.

## Project Structure

```
QuantumWarden/
├── src/
│   └── main.rs
├── test_plugin.wasm
├── test_plugin.wasm.manifest.json
├── classify.py
├── opcode_vector.json
├── plugin_exec_log.json
├── training_data.json
├── Cargo.toml
```

## Roadmap

* Phase 1: Secure execution with runtime limits
* Phase 2: Manifest enforcement
* Phase 3: Hash validation
* Phase 4: Execution logging
* Phase 5: Opcode analysis
* Phase 6: ML classification
* Phase 7+: Real-time telemetry and GPT-based summarization

## License

For academic, ethical security research, and educational purposes only. Commercial use or integration into production systems without approval is not permitted.
