//! This example changes the current text in Firefox's browser search bar from 
//! "Old search text" to "New search text". To run this example, open an instance
//! of Firefox and type "Old search text" in the search bar. If all goes well, when
//! you run this example as root, it should be replaced with "New search text",
//! although you may have to switch tabs and then switch back for it to render
//! the new text.

use raminspect::Result;
use raminspect::RamInspector;

fn main() -> Result<()> {
    // Iterate over all running Firefox instances
    for proc in raminspect::find_processes("/usr/lib/firefox") {
        let inspector = match RamInspector::new(proc.pid) {
            Ok(inspector) => inspector,
            Err(_) => continue,
        };

        // We have to make sure we're paused here since we're making modifications.

        inspector.do_while_paused(|| {
            let mut writes = Vec::new();
            for (proc_addr, memory_region) in inspector.search_for_term(b"Old search text")? {
                if !memory_region.writable() {
                    continue;
                }
    
                println!("Writing to process virtual address: 0x{:X}", proc_addr);
                writes.push((proc_addr, b"New search text".as_slice()));
            }
    
            // This is safe because modifying the text in the Firefox search bar will not crash
            // the browser or negatively impact system stability in any way.
            unsafe { inspector.write_bulk(writes.into_iter())? }
            Ok(())
        })?;
    }

    Ok(())
}