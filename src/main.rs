use clap::Parser;
use wasmtime::*;
use std::collections::HashMap;
use std::time::Instant;
use std::fs::File;
use std::io::{Write, Read};
use serde::{Serialize, Deserialize};
use wasmparser::{Parser as WasmParser, Payload};
use log::info;
use serde_json;
use sha2::{Sha256, Digest};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'f', long)]
    file: String,

    #[arg(short = 'x', long)]
    func: Option<String>,

    #[arg(short = 'i', long)]
    input: Option<String>,

    #[arg(short = 'g', long)]
    generate_hash: bool,

    #[arg(short = 't', long)]
    telemetry: bool,

    #[arg(short = 'c', long)]
    classify_only: bool,

    #[arg(short = 'o', long)]
    outdir: Option<String>,

    #[arg(long)]
    scan_only: bool,
}

#[derive(Serialize)]
struct ExecutionLog {
    file: String,
    function: String,
    success: bool,
    duration_ms: u128,
    error_message: Option<String>,
    fuel_consumed: Option<u64>,
    fuel_exhausted: bool,
    input: Option<String>,
    output: Option<String>,
    manifest_validated: bool,
    policy_violations: Vec<String>,
    integrity_verified: bool,
    plugin_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PluginManifest {
    name: String,
    version: String,
    description: Option<String>,
    functions: Vec<FunctionPolicy>,
    memory_limit: Option<u32>, // in pages (64KB each)
    fuel_limit: Option<u64>,
    trust_level: Option<TrustLevel>,
    requires_input: bool,
    allowed_input_types: Vec<String>, // e.g., ["i32", "string"]
    expected_hash: Option<String>, // SHA-256 hash of the .wasm file
    hash_algorithm: Option<String>, // Defaults to "sha256"
}

#[derive(Serialize, Deserialize, Debug)]
struct FunctionPolicy {
    name: String,
    signature: String, // e.g., "(i32) -> i32"
    max_execution_time_ms: Option<u64>,
    allowed_input_range: Option<(i32, i32)>, // min, max for numeric inputs
}

#[derive(Serialize, Deserialize, Debug)]
enum TrustLevel {
    Low,
    Medium,
    High,
    Trusted,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TelemetryEvent {
    timestamp: u64,
    event_type: TelemetryEventType,
    plugin_name: String,
    function_name: String,
    details: HashMap<String, serde_json::Value>,
    severity: TelemetrySeverity,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
enum TelemetryEventType {
    PluginLoad,
    FunctionCall,
    MemoryAccess,
    FuelConsumption,
    TrapOccurred,
    PolicyViolation,
    IntegrityCheck,
    ResourceUsage,
    SuspiciousActivity,
    PerformanceMetric,
    PluginClassification,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
enum TelemetrySeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
enum PluginClassification {
    Safe,
    Suspicious,
    Malicious,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug)]
struct PluginClassifier {
    model_type: String,
    confidence: f64,
    classification: PluginClassification,
    risk_factors: Vec<String>,
    opcode_analysis: OpcodeAnalysis,
}

#[derive(Serialize, Deserialize, Debug)]
struct OpcodeAnalysis {
    total_opcodes: u64,
    unique_opcodes: u64,
    suspicious_patterns: Vec<String>,
    complexity_score: f64,
    entropy_score: f64,
    opcode_frequency: BTreeMap<String, u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
enum SeverityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Debug)]
struct VulnerabilityReport {
    file: String,
    severity: SeverityLevel,
    score: f64,
    findings: Vec<String>,
    details: BTreeMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct MLModel {
    model_type: String,
    version: String,
    training_data_size: u64,
    accuracy: f64,
    features: Vec<String>,
    thresholds: ClassificationThresholds,
}

#[derive(Serialize, Deserialize, Debug)]
struct ClassificationThresholds {
    safe_threshold: f64,
    suspicious_threshold: f64,
    malicious_threshold: f64,
}

#[derive(Serialize, Deserialize, Debug)]
struct PluginTelemetry {
    plugin_id: String,
    session_id: String,
    start_time: u64,
    end_time: Option<u64>,
    events: Vec<TelemetryEvent>,
    metrics: PluginMetrics,
    trust_score: f64,
    risk_indicators: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PluginMetrics {
    total_function_calls: u64,
    total_memory_accessed: u64,
    total_fuel_consumed: u64,
    execution_time_ms: u64,
    trap_count: u64,
    policy_violations: u64,
    suspicious_activities: u64,
    average_response_time_ms: f64,
}

fn disassemble_wasm(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let parser = WasmParser::new(0);
    println!("Disassembling {}...", path);

    for payload in parser.parse_all(&data) {
        match payload? {
            Payload::Version { num, .. } => println!("WASM Version: {}", num),
            Payload::TypeSection(s) => println!("Type Section: {} types", s.count()),
            Payload::ImportSection(s) => println!("Imports: {} entries", s.count()),
            Payload::FunctionSection(s) => println!("Function Section: {} functions", s.count()),
            Payload::ExportSection(s) => println!("Exports: {} entries", s.count()),
            Payload::CodeSectionStart { count, .. } => println!("Code Section: {} functions", count),
            Payload::CodeSectionEntry(body) => {
                println!("  Function:");
                for op in body.get_operators_reader()? {
                    println!("    ▸ {:?}", op?);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn extract_opcode_features(path: &str) -> Result<BTreeMap<String, u64>, Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let parser = wasmparser::Parser::new(0);
    let mut opcode_counts = BTreeMap::new();

    for payload in parser.parse_all(&data) {
        match payload? {
            wasmparser::Payload::CodeSectionEntry(body) => {
                let reader = body.get_operators_reader()?;
                for op in reader {
                    let op = format!("{:?}", op?);
                    *opcode_counts.entry(op).or_insert(0) += 1;
                }
            }
            _ => {}
        }
    }

    Ok(opcode_counts)
}

fn scan_wasm_vulnerabilities(path: &str) -> Result<VulnerabilityReport, Box<dyn std::error::Error>> {
    let opcode_frequency = extract_opcode_features(path)?;
    let entropy_score = calculate_entropy(&opcode_frequency);
    let suspicious = detect_suspicious_patterns(&opcode_frequency);

    // Inspect imports for dangerous capabilities
    let mut dangerous_imports: Vec<String> = Vec::new();
    let data = std::fs::read(path)?;
    let parser = WasmParser::new(0);
    for payload in parser.parse_all(&data) {
        if let Payload::ImportSection(s) = payload? {
            for import in s {
                let import = import?;
                let module = import.module;
                let field = import.name;
                let sig = format!("{}::{}", module, field);
                // Heuristics: wasi fs/network interfaces
                if module.contains("wasi") || module.contains("socket") || field.contains("sock") || field.contains("path_") || field.contains("fd_") {
                    dangerous_imports.push(sig);
                }
            }
        }
    }

    let mut findings: Vec<String> = Vec::new();
    findings.extend(suspicious.iter().cloned());
    if !dangerous_imports.is_empty() { findings.push(format!("Dangerous imports: {}", dangerous_imports.join(", "))); }

    // Risk scoring
    let mut score = 0.0;
    if entropy_score > 2.0 { score += 2.0; }
    if opcode_frequency.len() as u64 > 10 { score += 1.0; }
    if !suspicious.is_empty() { score += 3.0; }
    if !dangerous_imports.is_empty() { score += 4.0; }

    let severity = if score < 1.0 { SeverityLevel::Info }
        else if score < 3.0 { SeverityLevel::Low }
        else if score < 5.0 { SeverityLevel::Medium }
        else if score < 7.0 { SeverityLevel::High }
        else { SeverityLevel::Critical };

    let mut details: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    details.insert("entropy".to_string(), serde_json::json!(entropy_score));
    details.insert("unique_opcodes".to_string(), serde_json::json!(opcode_frequency.len()));
    details.insert("dangerous_imports".to_string(), serde_json::json!(dangerous_imports));

    Ok(VulnerabilityReport { file: path.to_string(), severity, score, findings, details })
}

fn ensure_output_dir(outdir: &Option<String>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = outdir.clone().unwrap_or_else(|| ".".to_string());
    let p = PathBuf::from(dir);
    if !p.exists() { std::fs::create_dir_all(&p)?; }
    Ok(p)
}

fn write_json_in_dir(dir: &Path, filename: &str, json: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut path = PathBuf::from(dir);
    path.push(filename);
    std::fs::write(path, json)?;
    Ok(())
}

fn call_wasm_function(
    store: &mut Store<()>,
    func: &Func,
    input: Option<&str>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // Try different function signatures based on input
    if let Some(input_str) = input {
        // Try to parse as integer first
        if let Ok(input_int) = input_str.parse::<i32>() {
            // Try (i32) -> i32 signature
            if let Ok(typed_func) = func.typed::<i32, i32>(&mut *store) {
                let result = typed_func.call(&mut *store, input_int)?;
                return Ok(Some(result.to_string()));
            }
            // Try (i32) -> () signature
            if let Ok(typed_func) = func.typed::<i32, ()>(&mut *store) {
                typed_func.call(&mut *store, input_int)?;
                return Ok(Some("()".to_string()));
            }
        }
    }
    
    // Fallback to no-input function
    if let Ok(typed_func) = func.typed::<(), i32>(&mut *store) {
        let result = typed_func.call(&mut *store, ())?;
        return Ok(Some(result.to_string()));
    }
    if let Ok(typed_func) = func.typed::<(), ()>(&mut *store) {
        typed_func.call(&mut *store, ())?;
        return Ok(Some("()".to_string()));
    }
    
    Err("No compatible function signature found".into())
}

fn load_plugin_manifest(wasm_path: &str) -> Result<PluginManifest, Box<dyn std::error::Error>> {
    // Try to load manifest from .json file with same name as .wasm
    let manifest_path = wasm_path.replace(".wasm", ".manifest.json");
    
    if std::path::Path::new(&manifest_path).exists() {
        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PluginManifest = serde_json::from_str(&manifest_content)?;
        Ok(manifest)
    } else {
        // Create a default manifest with restrictive policies
        let default_manifest = PluginManifest {
            name: "Unknown Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Auto-generated manifest for plugin without policy file".to_string()),
            functions: vec![],
            memory_limit: Some(10), // 640KB default limit
            fuel_limit: Some(1000), // Conservative fuel limit
            trust_level: Some(TrustLevel::Low),
            requires_input: false,
            allowed_input_types: vec!["i32".to_string()],
            expected_hash: Some("45eb05dbe0a0a2df47788f382ba1d87adab365e30c522c7bc86e0d0e705b1395".to_string()),
            hash_algorithm: Some("sha256".to_string()),
        };
        Ok(default_manifest)
    }
}

fn validate_plugin_execution(
    manifest: &PluginManifest,
    function_name: &str,
    input: Option<&str>,
) -> Result<(), String> {
    // Check if function is allowed
    let function_policy = manifest.functions.iter()
        .find(|f| f.name == function_name)
        .ok_or_else(|| format!("Function '{}' not allowed by plugin policy", function_name))?;
    
    // Validate input if provided
    if let Some(input_str) = input {
        if manifest.requires_input && input.is_none() {
            return Err("Plugin requires input but none provided".to_string());
        }
        
        // Try to parse as integer and validate range
        if let Ok(input_int) = input_str.parse::<i32>() {
            if let Some((min, max)) = function_policy.allowed_input_range {
                if input_int < min || input_int > max {
                    return Err(format!("Input {} outside allowed range [{}, {}]", input_int, min, max));
                }
            }
        }
    }
    
    Ok(())
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init(); 
    let args = Args::parse();

    // Handle hash generation
    if args.generate_hash {
        println!("🔐 Generating plugin hash...");
        return generate_plugin_hash(&args.file);
    }

    // Handle classification-only mode
    if args.classify_only {
        println!("🤖 AI-Powered Plugin Classification (Analysis Only):");
        let opcode_vector = extract_opcode_features(&args.file)?;
        let classifier = classify_plugin(&opcode_vector);
        
        println!("  Model: {}", classifier.model_type);
        println!("  Confidence: {:.2}%", classifier.confidence * 100.0);
        println!("  Classification: {:?}", classifier.classification);
        if !classifier.risk_factors.is_empty() {
            println!("  Risk Factors: {}", classifier.risk_factors.join(", "));
        }
        
        let outdir = ensure_output_dir(&args.outdir)?;
        let json = serde_json::to_string_pretty(&classifier)?;
        write_json_in_dir(&outdir, "plugin_classification.json", &json)?;
        println!("Saved classification to {}/plugin_classification.json", outdir.display());
        return Ok(());
    }

    info!("Starting execution...");
    
    // Resolve output directory early
    let outdir = ensure_output_dir(&args.outdir)?;

    // Initialize telemetry
    let plugin_id = args.file.split('/').last().unwrap_or("unknown");
    let telemetry = TelemetryManager::new(plugin_id.to_string(), outdir.clone());
    
    // Load and validate plugin manifest
    println!("🔍 Loading plugin policy manifest...");
    let manifest = load_plugin_manifest(&args.file)?;
    println!("📋 Plugin: {} v{}", manifest.name, manifest.version);
    if let Some(desc) = &manifest.description {
        println!("📝 Description: {}", desc);
    }
    
    // Log plugin load event
    let mut details = HashMap::new();
    details.insert("version".to_string(), serde_json::Value::String(manifest.version.clone()));
    details.insert("trust_level".to_string(), serde_json::Value::String(format!("{:?}", manifest.trust_level)));
    telemetry.log_event(TelemetryEventType::PluginLoad, "main", details, TelemetrySeverity::Info);
    
    // Static vulnerability scan (pre-execution)
    println!("🧪 Static vulnerability scan...");
    let vuln_report = scan_wasm_vulnerabilities(&args.file)?;
    let vuln_json = serde_json::to_string_pretty(&vuln_report)?;
    write_json_in_dir(&outdir, "vuln_report.json", &vuln_json)?;
    println!("   Severity: {:?} (score {:.1})", vuln_report.severity, vuln_report.score);
    if args.scan_only {
        println!("Scan only mode enabled. Exiting after writing report to {}/vuln_report.json", outdir.display());
        telemetry.finalize_session()?;
        return Ok(());
    }

    // Verify plugin integrity
    let (integrity_verified, plugin_hash) = match verify_plugin_integrity(&args.file, &manifest) {
        Ok((verified, hash)) => (verified, hash),
        Err(integrity_error) => {
            let mut details = HashMap::new();
            details.insert("error".to_string(), serde_json::Value::String(integrity_error.clone()));
            telemetry.log_event(TelemetryEventType::IntegrityCheck, "main", details, TelemetrySeverity::Critical);
            println!("❌ Integrity check failed: {}", integrity_error);
            telemetry.finalize_session()?;
            return Err(integrity_error.into());
        }
    };
    
    // Log integrity check
    let mut details = HashMap::new();
    details.insert("verified".to_string(), serde_json::Value::Bool(integrity_verified));
    if let Some(hash) = &plugin_hash {
        details.insert("hash".to_string(), serde_json::Value::String(hash.clone()));
    }
    telemetry.log_event(TelemetryEventType::IntegrityCheck, "main", details, TelemetrySeverity::Info);
    
    // Validate execution request
    println!("⚖️  Validating execution policy...");
    let mut policy_violations: Vec<String> = Vec::new();
    
    if let Err(e) = validate_plugin_execution(&manifest, &args.func.as_deref().unwrap_or(""), args.input.as_deref()) {
        policy_violations.push(e);
    }

    let manifest_validated = policy_violations.is_empty();

    if !manifest_validated {
        let mut details = HashMap::new();
        details.insert("violations".to_string(), serde_json::Value::Array(
            policy_violations.iter().map(|v| serde_json::Value::String(v.clone())).collect()
        ));
        telemetry.log_event(TelemetryEventType::PolicyViolation, "main", details, TelemetrySeverity::Error);
        
        println!("❌ Policy violations detected:");
        for violation in &policy_violations {
            println!(" - {}", violation);
        }
        telemetry.finalize_session()?;
        return Err("Plugin policy violations detected. Execution aborted.".into());
    }
    println!("✅ Policy validation passed");
    
    let engine = Engine::default();
    let module = Module::from_file(&engine, &args.file)?;
    let mut store = Store::new(&engine, ());

    let instance = Instance::new(&mut store, &module, &[])?;
    let func = instance
        .get_func(&mut store, &args.func.as_deref().unwrap())
        .ok_or("Function not found")?;

    let start = Instant::now();
    
    // Enhanced fuel exhaustion handling with graceful recovery
    let execution_result = match call_wasm_function(&mut store, &func, args.input.as_deref()) {
        Ok(output) => {
            // Store the output for logging
            let output_str = output.clone();
            
            // Log successful function call
            let mut details = HashMap::new();
            if let Some(input) = &args.input {
                details.insert("input".to_string(), serde_json::Value::String(input.clone()));
            }
            if let Some(output) = &output {
                details.insert("output".to_string(), serde_json::Value::String(output.clone()));
            }
            telemetry.log_event(TelemetryEventType::FunctionCall, &args.func.as_deref().unwrap_or(""), details, TelemetrySeverity::Info);
            
            Ok(output_str)
        }
        Err(e) => {
            // Check if this is a fuel exhaustion error
            if let Some(trap) = e.downcast_ref::<wasmtime::Trap>() {
                match trap {
                    wasmtime::Trap::OutOfFuel => {
                        let mut details = HashMap::new();
                        details.insert("trap_type".to_string(), serde_json::Value::String("OutOfFuel".to_string()));
                        telemetry.log_event(TelemetryEventType::TrapOccurred, &args.func.as_deref().unwrap_or(""), details, TelemetrySeverity::Warning);
                        
                        println!("Fuel exhaustion detected! Plugin consumed all available resources.");
                        println!("Consider:");
                        println!(" - Increasing fuel limits");
                        println!(" - Optimizing the plugin code");
                        println!(" - Breaking complex operations into smaller chunks");
                        Err(e) // Re-throw the error for proper logging
                    }
                    _ => {
                        let mut details = HashMap::new();
                        details.insert("trap_type".to_string(), serde_json::Value::String(format!("{:?}", trap)));
                        telemetry.log_event(TelemetryEventType::TrapOccurred, &args.func.as_deref().unwrap_or(""), details, TelemetrySeverity::Error);
                        
                        println!("WebAssembly trap detected: {}", trap);
                        Err(e)
                    }
                }
            } else {
                let mut details = HashMap::new();
                details.insert("error".to_string(), serde_json::Value::String(e.to_string()));
                telemetry.log_event(TelemetryEventType::SuspiciousActivity, &args.func.as_deref().unwrap_or(""), details, TelemetrySeverity::Error);
                
                println!(" Execution error: {}", e);
                Err(e)
            }
        }
    };
    
    let duration = start.elapsed();
    
    // Log performance metrics
    let mut details = HashMap::new();
    details.insert("execution_time_ms".to_string(), serde_json::Value::Number(serde_json::Number::from(duration.as_millis() as u64)));
    details.insert("duration_ns".to_string(), serde_json::Value::Number(serde_json::Number::from(duration.as_nanos() as u64)));
    telemetry.log_event(TelemetryEventType::PerformanceMetric, &args.func.as_deref().unwrap_or(""), details, TelemetrySeverity::Info);

    let (success, error_message, fuel_exhausted, output) = match &execution_result {
        Ok(output_str) => (true, None, false, output_str.clone()),
        Err(e) => {
            // Try to downcast to wasmtime::Trap and check for OutOfFuel
            if let Some(trap) = e.downcast_ref::<wasmtime::Trap>() {
                if *trap == wasmtime::Trap::OutOfFuel {
                    (false, Some("Execution failed: all fuel consumed by WebAssembly".to_string()), true, None)
                } else {
                    (false, Some(format!("Trap: {}", trap)), false, None)
                }
            } else {
                (false, Some(e.to_string()), false, None)
            }
        }
    };

    let log = ExecutionLog {
        file: args.file.clone(),
        function: args.func.as_deref().unwrap_or("").to_string(),
        success,
        duration_ms: duration.as_millis(),
        error_message: error_message.clone(),
        fuel_consumed: None, // We'll add fuel monitoring in a future enhancement
        fuel_exhausted,
        input: args.input.clone(),
        output: output.clone(),
        manifest_validated,
        policy_violations,
        integrity_verified,
        plugin_hash,
    };

    let json = serde_json::to_string_pretty(&log)?;
    let mut logfile = PathBuf::from(&outdir);
    logfile.push("execution_log.json");
    let mut file = File::create(logfile)?;
    file.write_all(json.as_bytes())?;

    if success {
        println!(" Plugin executed successfully in {} ms", log.duration_ms);
        if let Some(output) = &output {
            println!(" Result: {}", output);
        }
    } else {
        if fuel_exhausted {
            println!(" Plugin execution failed due to fuel exhaustion in {} ms", log.duration_ms);
            println!(" Resource consumption exceeded limits");
        } else {
            println!(" Plugin execution failed in {} ms: {}", 
                     log.duration_ms, 
                     error_message.unwrap_or_else(|| "Unknown error".to_string()));
        }
    }

    disassemble_wasm(&args.file)?;

    let opcode_vector = extract_opcode_features(&args.file)?;
    println!("\nOpcode Frequency Vector:");
    for (opcode, count) in &opcode_vector {
        println!("  {}: {}", opcode, count);
    }

    let json = serde_json::to_string_pretty(&opcode_vector)?;
    write_json_in_dir(&outdir, "opcode_vector.json", &json)?;
    println!("Saved vector to {}/opcode_vector.json", outdir.display());

    // AI-powered plugin classification
    println!("\n🤖 AI-Powered Plugin Classification:");
    let classifier = classify_plugin(&opcode_vector);
    
    // Log classification event
    let mut details = HashMap::new();
    details.insert("classification".to_string(), serde_json::Value::String(format!("{:?}", classifier.classification)));
    details.insert("confidence".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(classifier.confidence).unwrap()));
    details.insert("model_type".to_string(), serde_json::Value::String(classifier.model_type.clone()));
    telemetry.log_event(TelemetryEventType::PluginClassification, "classifier", details, 
                       if classifier.classification == PluginClassification::Safe { TelemetrySeverity::Info } 
                       else if classifier.classification == PluginClassification::Suspicious { TelemetrySeverity::Warning }
                       else { TelemetrySeverity::Error });
    
    println!("  Model: {}", classifier.model_type);
    println!("  Confidence: {:.2}%", classifier.confidence * 100.0);
    println!("  Classification: {:?}", classifier.classification);
    if !classifier.risk_factors.is_empty() {
        println!("  Risk Factors: {}", classifier.risk_factors.join(", "));
    }
    
    // Block execution if classified as malicious
    if classifier.classification == PluginClassification::Malicious {
        println!("❌ MALICIOUS PLUGIN DETECTED! Execution blocked.");
        println!("🚨 This plugin has been classified as potentially harmful.");
        telemetry.finalize_session()?;
        return Err("Plugin classified as malicious - execution blocked".into());
    }
    
    // Warn for suspicious plugins
    if classifier.classification == PluginClassification::Suspicious {
        println!("⚠️  SUSPICIOUS PLUGIN DETECTED! Proceed with caution.");
    }

    let json = serde_json::to_string_pretty(&classifier)?;
    write_json_in_dir(&outdir, "plugin_classification.json", &json)?;
    println!("Saved classification to {}/plugin_classification.json", outdir.display());

    telemetry.finalize_session()?;
    Ok(())
}

fn calculate_entropy(frequencies: &BTreeMap<String, u64>) -> f64 {
    let total: u64 = frequencies.values().sum();
    if total == 0 {
        return 0.0;
    }
    
    let mut entropy = 0.0;
    for &count in frequencies.values() {
        if count > 0 {
            let probability = count as f64 / total as f64;
            entropy -= probability * probability.log2();
        }
    }
    entropy
}

fn detect_suspicious_patterns(opcode_frequency: &BTreeMap<String, u64>) -> Vec<String> {
    let mut patterns = Vec::new();
    
    // Check for crypto mining patterns
    let crypto_indicators = ["i64.rem", "i64.mul", "i64.add", "i64.xor", "i64.and"];
    let crypto_count: u64 = crypto_indicators.iter()
        .map(|&opcode| opcode_frequency.get(opcode).unwrap_or(&0))
        .sum();
    if crypto_count > 50 {
        patterns.push("High crypto operation frequency".to_string());
    }
    
    // Check for obfuscation patterns
    let obfuscation_indicators = ["call", "call_indirect", "br", "br_if"];
    let obfuscation_count: u64 = obfuscation_indicators.iter()
        .map(|&opcode| opcode_frequency.get(opcode).unwrap_or(&0))
        .sum();
    if obfuscation_count > 100 {
        patterns.push("Potential code obfuscation".to_string());
    }
    
    // Check for memory manipulation
    let memory_ops = ["i32.load", "i32.store", "memory.grow", "memory.size"];
    let memory_count: u64 = memory_ops.iter()
        .map(|&opcode| opcode_frequency.get(opcode).unwrap_or(&0))
        .sum();
    if memory_count > 200 {
        patterns.push("Excessive memory operations".to_string());
    }
    
    // Check for loops and recursion
    let loop_ops = ["loop", "block", "if", "br"];
    let loop_count: u64 = loop_ops.iter()
        .map(|&opcode| opcode_frequency.get(opcode).unwrap_or(&0))
        .sum();
    if loop_count > 150 {
        patterns.push("Complex control flow detected".to_string());
    }
    
    patterns
}

fn classify_plugin(opcode_frequency: &BTreeMap<String, u64>) -> PluginClassifier {
    let total_opcodes: u64 = opcode_frequency.values().sum();
    let unique_opcodes = opcode_frequency.len() as u64;
    let entropy_score = calculate_entropy(opcode_frequency);
    let suspicious_patterns = detect_suspicious_patterns(opcode_frequency);
    
    // Calculate complexity score
    let complexity_score = (unique_opcodes as f64 / total_opcodes as f64) * entropy_score;
    
    // Simple rule-based classification
    let mut risk_score = 0.0;
    let mut risk_factors = Vec::new();
    
    // High entropy might indicate obfuscation
    if entropy_score > 2.0 {  // Lowered from 4.0
        risk_score += 0.3;
        risk_factors.push("High entropy (potential obfuscation)".to_string());
    }
    
    // Many unique opcodes might indicate complex logic
    if unique_opcodes > 10 {  // Lowered from 50
        risk_score += 0.2;
        risk_factors.push("High opcode diversity".to_string());
    }
    
    // Suspicious patterns
    if !suspicious_patterns.is_empty() {
        risk_score += 0.4;
        risk_factors.extend(suspicious_patterns.clone());
    }
    
    // Determine classification based on risk score
    let (classification, confidence) = if risk_score < 0.2 {  // Lowered from 0.3
        (PluginClassification::Safe, 1.0 - risk_score)
    } else if risk_score < 0.5 {  // Lowered from 0.7
        (PluginClassification::Suspicious, 0.8 - risk_score * 0.5)
    } else {
        (PluginClassification::Malicious, risk_score)
    };
    
    let opcode_analysis = OpcodeAnalysis {
        total_opcodes,
        unique_opcodes,
        suspicious_patterns,
        complexity_score,
        entropy_score,
        opcode_frequency: opcode_frequency.clone(),
    };
    
    PluginClassifier {
        model_type: "Rule-based Classifier v1.0".to_string(),
        confidence,
        classification,
        risk_factors,
        opcode_analysis,
    }
}

struct TelemetryManager {
    telemetry: Arc<Mutex<PluginTelemetry>>,
    log_file: String,
}

impl TelemetryManager {
    fn new(plugin_id: String, outdir: PathBuf) -> Self {
        let session_id = format!("session_{}", SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis());
        
        let telemetry = PluginTelemetry {
            plugin_id: plugin_id.clone(),
            session_id,
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            end_time: None,
            events: Vec::new(),
            metrics: PluginMetrics {
                total_function_calls: 0,
                total_memory_accessed: 0,
                total_fuel_consumed: 0,
                execution_time_ms: 0,
                trap_count: 0,
                policy_violations: 0,
                suspicious_activities: 0,
                average_response_time_ms: 0.0,
            },
            trust_score: 100.0,
            risk_indicators: Vec::new(),
        };
        
        let mut p = outdir;
        p.push(format!("telemetry_{}.json", plugin_id));
        Self { telemetry: Arc::new(Mutex::new(telemetry)), log_file: p.display().to_string() }
    }
    
    fn log_event(&self, event_type: TelemetryEventType, function_name: &str, 
                 details: HashMap<String, serde_json::Value>, severity: TelemetrySeverity) {
        let mut telemetry = self.telemetry.lock().unwrap();
        let event = TelemetryEvent {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type,
            plugin_name: telemetry.plugin_id.clone(),
            function_name: function_name.to_string(),
            details,
            severity,
        };
        
        telemetry.events.push(event.clone());
        
        // Update metrics based on event type
        match event.event_type {
            TelemetryEventType::FunctionCall => telemetry.metrics.total_function_calls += 1,
            TelemetryEventType::TrapOccurred => telemetry.metrics.trap_count += 1,
            TelemetryEventType::PolicyViolation => telemetry.metrics.policy_violations += 1,
            TelemetryEventType::SuspiciousActivity => telemetry.metrics.suspicious_activities += 1,
            _ => {}
        }
        
        // Real-time logging
        println!("📡 [TELEMETRY] {:?} - {} - {:?}", 
                 severity, function_name, event_type);
    }
    
    fn finalize_session(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut telemetry = self.telemetry.lock().unwrap();
        telemetry.end_time = Some(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs());
        
        // Calculate trust score based on behavior
        let mut trust_score = 100.0;
        if telemetry.metrics.trap_count > 0 {
            trust_score -= telemetry.metrics.trap_count as f64 * 10.0;
        }
        if telemetry.metrics.policy_violations > 0 {
            trust_score -= telemetry.metrics.policy_violations as f64 * 20.0;
        }
        if telemetry.metrics.suspicious_activities > 0 {
            trust_score -= telemetry.metrics.suspicious_activities as f64 * 15.0;
        }
        telemetry.trust_score = trust_score.max(0.0);
        
        // Save telemetry to file
        let json = serde_json::to_string_pretty(&*telemetry)?;
        std::fs::write(&self.log_file, json)?;
        
        println!("📊 [TELEMETRY] Session finalized:");
        println!("   Trust Score: {:.1}%", telemetry.trust_score);
        println!("   Function Calls: {}", telemetry.metrics.total_function_calls);
        println!("   Traps: {}", telemetry.metrics.trap_count);
        println!("   Policy Violations: {}", telemetry.metrics.policy_violations);
        println!("   Log saved to: {}", self.log_file);
        
        Ok(())
    }
}

fn calculate_file_hash(file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

fn verify_plugin_integrity(wasm_path: &str, manifest: &PluginManifest) -> Result<(bool, Option<String>), String> {
    // If no hash is expected, skip verification
    if manifest.expected_hash.is_none() {
        println!("⚠️  No hash verification required for this plugin");
        return Ok((true, None));
    }
    
    let expected_hash = manifest.expected_hash.as_ref().unwrap();
    let actual_hash = calculate_file_hash(wasm_path)
        .map_err(|e| format!("Failed to calculate hash: {}", e))?;
    
    println!("🔍 Verifying plugin integrity...");
    println!("   Expected hash: {}", expected_hash);
    println!("   Actual hash:   {}", actual_hash);
    
    if actual_hash == *expected_hash {
        println!("✅ Plugin integrity verified - hash matches");
        Ok((true, Some(actual_hash)))
    } else {
        println!("❌ Plugin integrity check failed - hash mismatch!");
        println!("   This plugin may have been tampered with!");
        Err(format!("Plugin hash verification failed. Expected: {}, Got: {}", expected_hash, actual_hash))
    }
}

fn generate_plugin_hash(wasm_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let hash = calculate_file_hash(wasm_path)?;
    println!("🔐 Plugin hash for {}: {}", wasm_path, hash);
    println!("💡 Add this hash to your manifest's 'expected_hash' field");
    Ok(())
}
