//! # Purpose
//! 
//! This example is a CLI application that can find and replace arbitrary
//! data in an arbitrary process, using the raminspect library as a backend.
//! 
//! # Usage
//! 
//! `sudo cargo run --example replacemem --release -- <pid> <search term> <replacement>`
//!
//! Or if you want to install this as a command line application, you may build it using this command:
//! 
//! `cargo build --release --example replacemem`
//!
//! And then copy the output to /usr/bin like so:
//! 
//! `sudo cp target/release/examples/replacemem /usr/bin/replacemem`
//! 
//! And then use the resulting executable like this after you refresh your shell:
//! 
//! `sudo replacemem <pid> <string search term> <string replacement>`

use raminspect::Result;
use raminspect::RamInspector;

fn exit_err(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    eprintln!("Program usage: replacemem pidnumber \"searchterm\" \"replacement\"");
    std::process::exit(1);
}

fn main() {
    let mut args = std::env::args();
    let pid_parse_err = "Expected a number as the first argument";

    // Skip the first argument which is the program name on Unix systems
    args.next();
    
    let pid = args.next().unwrap_or_else(|| exit_err(pid_parse_err)).parse::<i32>().unwrap_or_else(|_| {
        exit_err(pid_parse_err)
    });

    let search_term = args.next().unwrap_or_else(|| exit_err("Expected three arguments."));
    let replacement_term = args.next().unwrap_or_else(|| exit_err("Expected three arguments."));

    if args.next().is_some() {
        exit_err("Expected no more than three arguments.");
    }

    fn inspect_process(pid: i32, search_term: &str, replacement_term: &str) -> Result<()> {
        let mut writes = Vec::new();
        let inspector = RamInspector::new(pid)?;
        for (result_addr, memory_region) in inspector.search_for_term(search_term.as_bytes())? {
            if !memory_region.writable() {
                continue;
            }

            println!("Writing to address: 0x{:X}", result_addr);
            writes.push((result_addr, replacement_term.as_bytes()));
        }
        
        unsafe { inspector.write_bulk(writes.into_iter())? }
        Ok(())
    }

    if let Err(error) = inspect_process(pid, &search_term, &replacement_term) {
        exit_err(&format!("{:?}", error));
    }
}