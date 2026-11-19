//! Timing harness for the scan hot path.
//!
//! Run with `cargo bench`. There is no external harness on purpose: the numbers
//! are wall-clock medians, which is enough to compare two builds of this crate.
//!
//! Three numbers are reported:
//!
//! - a full scan of `.text` with a pattern that never matches, which walks the
//!   whole section and exercises the scan hot path;
//! - a full module scan, with the readable and blocked byte counts reported
//!   separately to describe how much memory the scanner can skip;
//! - a one-byte query repeated many times, which measures the whole tiny query,
//!   including setup, matching, teardown and timer overhead.

#[path = "../src/page_protection.rs"]
mod page_protection;

use sigmatch::Seeker;
use std::hint::black_box;
use std::io;
use std::time::{Duration, Instant};
use windows::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

/// Count how much of the image range is committed and readable. The number
/// matters because the run builder can only skip what is actually blocked.
fn census(base: usize, size: usize) -> io::Result<(usize, usize)> {
    let mut readable = 0usize;
    let mut blocked = 0usize;
    let end = base.checked_add(size).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "image range overflows usize")
    })?;
    let mut current = base;
    while current < end {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let written = unsafe {
            VirtualQuery(
                Some(current as *const _),
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("VirtualQuery at {current:#x}: {error}"),
            ));
        }
        let region_base = info.BaseAddress as usize;
        let region_end = region_base
            .checked_add(info.RegionSize)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "queried region overflows usize")
            })?
            .min(end);
        if region_base > current || region_end <= current {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("VirtualQuery returned an invalid region at {current:#x}"),
            ));
        }
        let span = region_end - current;
        if page_protection::region_is_readable(&info) {
            readable += span;
        } else {
            blocked += span;
        }
        current = region_end;
    }
    Ok((readable, blocked))
}

fn main() -> io::Result<()> {
    let seeker = match Seeker::with_name("ntdll.dll") {
        Ok(seeker) => seeker,
        Err(_) => Seeker::with_name("main").expect("bind a module"),
    };
    let mut sections = seeker.sections();
    let text = sections.remove(".text").expect(".text section");
    println!(
        "module {}: {} bytes, .text: {} bytes at {:#x}",
        seeker.module_name(),
        seeker.module_size(),
        text.section_size,
        text.section_base
    );
    let (readable, blocked) = census(seeker.module_base(), seeker.module_size())?;
    println!(
        "image range: {} bytes readable, {} bytes blocked ({:.1}%)",
        readable,
        blocked,
        100.0 * blocked as f64 / (readable + blocked).max(1) as f64
    );
    if let Ok(main) = Seeker::with_name("main") {
        let (readable, blocked) = census(main.module_base(), main.module_size())?;
        println!(
            "{}: {} bytes readable, {} bytes blocked ({:.1}%)",
            main.module_name(),
            readable,
            blocked,
            100.0 * blocked as f64 / (readable + blocked).max(1) as f64
        );
    }

    // Sixteen bytes that should not appear anywhere in .text.
    let pattern = "DE AD BE EF 13 37 C0 DE DE AD BE EF 13 37 C0 DE";

    for _ in 0..20 {
        let hits = seeker
            .scan(pattern)
            .unwrap()
            .in_section(".text")
            .all()
            .unwrap()
            .count();
        black_box(hits);
    }

    const RUNS: usize = 200;
    let mut samples = Vec::with_capacity(RUNS);
    let mut hits = 0;
    for _ in 0..RUNS {
        let start = Instant::now();
        hits += seeker
            .scan(pattern)
            .unwrap()
            .in_section(".text")
            .all()
            .unwrap()
            .count();
        samples.push(start.elapsed());
    }
    let full = median(samples);
    let throughput = text.section_size as f64 / full.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "full .text scan: {:?} ({:.1} MiB/s, {} hits)",
        full, throughput, hits
    );

    // Scan the whole image, including section gaps; the census above reports
    // whether this particular module has any blocked memory to skip.
    for _ in 0..10 {
        let hits = seeker.scan(pattern).unwrap().all().unwrap().count();
        black_box(hits);
    }
    let mut samples = Vec::with_capacity(RUNS);
    let mut hits = 0;
    for _ in 0..RUNS {
        let start = Instant::now();
        hits += seeker.scan(pattern).unwrap().all().unwrap().count();
        samples.push(start.elapsed());
    }
    let whole = median(samples);
    let throughput = seeker.module_size() as f64 / whole.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "whole module scan: {:?} ({:.1} MiB/s, {} hits)",
        whole, throughput, hits
    );

    // The pattern is parsed once outside the loop. Query setup, one candidate,
    // teardown and timer overhead all remain in the measurement.
    const TINY_RUNS: usize = 20_000;
    let anchor = text.section_base + 16;
    let tiny = sigmatch::Pattern::signature("90").unwrap();
    let mut samples = Vec::with_capacity(TINY_RUNS);
    for _ in 0..TINY_RUNS {
        let start = Instant::now();
        let hit = seeker
            .scan(&tiny)
            .unwrap()
            .in_section(".text")
            .forward_from(anchor)
            .within(1)
            .all()
            .unwrap()
            .count();
        black_box(hit);
        samples.push(start.elapsed());
    }
    println!("one-byte query: {:?}", median(samples));
    Ok(())
}
