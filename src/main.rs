use clap::Parser;
use wasmtime::*;
use std::collections::HashMap;
use std::time::Instant;
use std::fs::File;
use std::io::Write;
use serde::Serialize;
use wasmparser::{Parser as WasmParser, Payload};
use log::info;
use serde_json;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'f', long)]
    file: String,

    #[arg(short = 'x', long)]
    func: String,
}

#[derive(Serialize)]
struct ExecutionLog {
    file: String,
    function: String,
    success: bool,
    duration_ms: u128,
    error_message: Option<String>,
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

fn extract_opcode_features(path: &str) -> Result<HashMap<String, usize>, Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let parser = wasmparser::Parser::new(0);
    let mut opcode_counts = HashMap::new();

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


fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init(); 
    let args = Args::parse();

    info!("Starting execution...");
    
    let engine = Engine::default();
    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config)?;
    let module = Module::from_file(&engine, &args.file)?;
    let mut store = Store::new(&engine, ());
    // Add a reasonable amount of fuel (e.g., 10_000)
    store.add_fuel(10_000)?;

    let instance = Instance::new(&mut store, &module, &[])?;
    let func = instance
        .get_func(&mut store, &args.func)
        .ok_or("Function not found")?;

    let typed_func = func.typed::<(), ()>(&store)?;

    let start = Instant::now();
    let execution_result = typed_func.call(&mut store, ());
    let duration = start.elapsed();

    let (success, error_message) = match &execution_result {
        Ok(_) => (true, None),
        Err(e) => {
            // Try to downcast to wasmtime::Trap and check for OutOfFuel
            if let Some(trap) = e.downcast_ref::<wasmtime::Trap>() {
                if *trap == wasmtime::Trap::OutOfFuel {
                    (false, Some("Execution failed: all fuel consumed by WebAssembly".to_string()))
                } else {
                    (false, Some(format!("Trap: {}", trap)))
                }
            } else {
                (false, Some(e.to_string()))
            }
        }
    };

    let log = ExecutionLog {
        file: args.file.clone(),
        function: args.func,
        success,
        duration_ms: duration.as_millis(),
        error_message: error_message.clone(),
    };

    let json = serde_json::to_string_pretty(&log)?;
    let mut file = File::create("execution_log.json")?;
    file.write_all(json.as_bytes())?;

    if success {
        println!("Plugin executed successfully in {} ms", log.duration_ms);
    } else {
        println!("Plugin execution failed in {} ms: {}", 
                 log.duration_ms, 
                 error_message.unwrap_or_else(|| "Unknown error".to_string()));
    }

    disassemble_wasm(&args.file)?;

    let opcode_vector = extract_opcode_features(&args.file)?;
    println!("\nOpcode Frequency Vector:");
    for (opcode, count) in &opcode_vector {
        println!("  {}: {}", opcode, count);
    }

    let json = serde_json::to_string_pretty(&opcode_vector)?;
    std::fs::write("opcode_vector.json", json)?;
    println!("Saved vector to opcode_vector.json");

    Ok(())
}
