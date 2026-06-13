use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "delink",
    version,
    about = "Split a debug .so or .exe into .o/.obj files"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Report sections, dynamic relocations, and DWARF compilation units.
    Inspect { input: PathBuf },

    /// Emit a single CU as an ET_REL `.o` file (no relocations yet; M2 validation).
    Emit {
        input: PathBuf,
        /// Match against the suffix of the CU name (e.g. `bacolor.cpp`).
        #[arg(long)]
        cu: String,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        comdat: bool,
        #[arg(long)]
        dwarf: bool,
        /// Emit one `.text.<mangled>` per function (default: single `.text`).
        #[arg(long)]
        per_function_sections: bool,
    },

    /// List CUs matching a substring, sorted by .text size ascending.
    ListCus {
        input: PathBuf,
        #[arg(long, default_value = "")]
        contains: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// Dump a relocatable `.o` file's sections and symbols (for validation).
    Readobj { input: PathBuf },

    /// Emit `__shared_data.o` carrying .rodata / .bss (and eventually .data).
    EmitShared {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Split the whole `.so` into one `.o` per CU plus `__shared_data.o`.
    Split {
        input: PathBuf,
        #[arg(short, long)]
        outdir: PathBuf,
        #[arg(long)]
        comdat: bool,
        #[arg(long)]
        dwarf: bool,
        /// Emit one `.text.<mangled>` per function (default: single `.text`).
        /// Required for `--comdat` and for `ld --gc-sections` to work.
        #[arg(long)]
        per_function_sections: bool,
    },

    // -----------------------------------------------------------------------
    // Windows PE + PDB subcommands
    // -----------------------------------------------------------------------
    /// Inspect a Windows PE (.exe) and its PDB: print sections, imports, and CU list.
    PeInspect {
        /// Path to the PE executable (.exe or .dll).
        input: PathBuf,
        /// Path to the matching PDB file.
        #[arg(long)]
        pdb: PathBuf,
    },

    /// List PDB modules (CUs) sorted by .text size.
    PeListCus {
        input: PathBuf,
        #[arg(long)]
        pdb: PathBuf,
        #[arg(long, default_value = "")]
        contains: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// Split a PE + PDB into one COFF `.obj` per module plus `__shared_data.obj`.
    PeSplit {
        /// Path to the PE executable (.exe or .dll).
        input: PathBuf,
        /// Path to the matching PDB file.
        #[arg(long)]
        pdb: PathBuf,
        /// Output directory for the `.obj` files.
        #[arg(short, long)]
        outdir: PathBuf,
    },

    // -----------------------------------------------------------------------
    // Mach-O subcommands
    // -----------------------------------------------------------------------
    /// Inspect a Mach-O binary: print sections and DWARF compilation units.
    MachoInspect {
        /// Path to the Mach-O executable or dylib.
        input: PathBuf,
    },

    /// List Mach-O DWARF compilation units sorted by .text size.
    MachoListCus {
        input: PathBuf,
        #[arg(long, default_value = "")]
        contains: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// Split a Mach-O binary into one `.o` per DWARF CU plus `__shared_data.o`.
    MachoSplit {
        /// Path to the Mach-O executable or dylib.
        input: PathBuf,
        /// Output directory for the `.o` files.
        #[arg(short, long)]
        outdir: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Inspect { input } => cmd_inspect(&input),
        Cmd::Emit {
            input,
            cu,
            output,
            comdat,
            dwarf,
            per_function_sections,
        } => cmd_emit(&input, &cu, &output, comdat, dwarf, per_function_sections),
        Cmd::ListCus {
            input,
            contains,
            limit,
        } => cmd_list_cus(&input, &contains, limit),
        Cmd::Readobj { input } => cmd_readobj(&input),
        Cmd::EmitShared { input, output } => cmd_emit_shared(&input, &output),
        Cmd::Split {
            input,
            outdir,
            comdat,
            dwarf,
            per_function_sections,
        } => cmd_split(&input, &outdir, comdat, dwarf, per_function_sections),
        Cmd::PeInspect { input, pdb } => cmd_pe_inspect(&input, &pdb),
        Cmd::PeListCus {
            input,
            pdb,
            contains,
            limit,
        } => cmd_pe_list_cus(&input, &pdb, &contains, limit),
        Cmd::PeSplit { input, pdb, outdir } => cmd_pe_split(&input, &pdb, &outdir),
        Cmd::MachoInspect { input } => cmd_macho_inspect(&input),
        Cmd::MachoListCus {
            input,
            contains,
            limit,
        } => cmd_macho_list_cus(&input, &contains, limit),
        Cmd::MachoSplit { input, outdir } => cmd_macho_split(&input, &outdir),
    }
}

fn cmd_split(
    path: &Path,
    outdir: &Path,
    comdat: bool,
    dwarf: bool,
    per_function_sections: bool,
) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    tracing::info!("indexing DWARF…");
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    tracing::info!("building symbol resolver…");
    let symbols = delink_core::symbols::GlobalSymbols::build(&binary, &idx)?;
    tracing::info!(
        "emitting {} CUs in parallel",
        idx.units
            .iter()
            .filter(|u| u.functions.iter().any(|f| f.size > 0))
            .count()
    );
    let outcomes = delink_emit::split_all(
        &binary,
        &idx,
        &symbols,
        outdir,
        comdat,
        dwarf,
        per_function_sections,
    )?;
    let shared = outdir.join("__shared_data.o");
    let shared_stats = delink_emit::emit_shared_data(
        &binary,
        &symbols,
        delink_emit::SharedDataOptions { dwarf },
        &shared,
    )?;

    let mut total = delink_emit::EmitStats::default();
    let mut failures = 0usize;
    for o in &outcomes {
        match &o.result {
            Ok(s) => {
                total.text_bytes += s.text_bytes;
                total.local_symbols += s.local_symbols;
                total.undef_symbols += s.undef_symbols;
                total.relocations += s.relocations;
                total.unresolved_calls += s.unresolved_calls;
                total.instructions += s.instructions;
                total.adrp_seen += s.adrp_seen;
                total.adrp_paired += s.adrp_paired;
                total.adrp_unresolved += s.adrp_unresolved;
            }
            Err(e) => {
                failures += 1;
                tracing::warn!(cu = %o.cu_name, error = %e, "emit failed");
            }
        }
    }
    println!(
        "split complete: {} CUs ({} failed)\n  {} bytes .text, {} instructions\n  {} local + {} undef symbols\n  {} relocs ({} unresolved calls, {} unresolved adrps of {})\n  shared data: rodata={} data={} data.rel.ro={} bss={}",
        outcomes.len() - failures,
        failures,
        total.text_bytes,
        total.instructions,
        total.local_symbols,
        total.undef_symbols,
        total.relocations,
        total.unresolved_calls,
        total.adrp_unresolved,
        total.adrp_seen,
        shared_stats.rodata_bytes,
        shared_stats.data_bytes,
        shared_stats.data_rel_ro_bytes,
        shared_stats.bss_bytes,
    );
    Ok(())
}

fn cmd_emit_shared(path: &Path, output: &Path) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    let symbols = delink_core::symbols::GlobalSymbols::build(&binary, &idx)?;
    let stats = delink_emit::emit_shared_data(
        &binary,
        &symbols,
        delink_emit::SharedDataOptions { dwarf: true },
        output,
    )?;
    println!(
        "wrote {}\n  .rodata: {} bytes\n  .data: {} bytes\n  .data.rel.ro: {} bytes\n  .init_array: {} bytes\n  .fini_array: {} bytes\n  .bss: {} bytes\n  .eh_frame: {} bytes ({} FDE relocs)\n  data relocs: {} RELATIVE + {} ABS64 + {} GLOB_DAT translated; {} skipped, {} unresolved",
        output.display(),
        stats.rodata_bytes,
        stats.data_bytes,
        stats.data_rel_ro_bytes,
        stats.init_array_bytes,
        stats.fini_array_bytes,
        stats.bss_bytes,
        stats.eh_frame_bytes,
        stats.fde_relocs,
        stats.translated_relatives,
        stats.translated_abs64,
        stats.translated_glob_dat,
        stats.skipped_relocs,
        stats.unresolved_relocs,
    );
    Ok(())
}

fn cmd_readobj(path: &Path) -> Result<()> {
    use object::read::elf::{ElfFile64, FileHeader};
    use object::{Endianness, Object, ObjectSection, ObjectSymbol};

    let mmap = mmap_file(path)?;
    let elf = ElfFile64::<Endianness>::parse(&mmap[..])
        .with_context(|| format!("parse {}", path.display()))?;
    let endian = elf.elf_header().endian()?;
    let e_type = elf.elf_header().e_type(endian);
    let e_machine = elf.elf_header().e_machine(endian);

    println!("ELF  e_type=0x{:x} e_machine=0x{:x}", e_type, e_machine);
    println!("\nSECTIONS");
    for s in elf.sections() {
        let name = s.name().unwrap_or("<?>");
        println!(
            "  {:<24} addr={:#010x} size={:>8} kind={:?}",
            name,
            s.address(),
            s.size(),
            s.kind()
        );
    }

    println!("\nSYMBOLS");
    for sym in elf.symbols() {
        let name = sym.name().unwrap_or("<?>");
        if name.is_empty() {
            continue;
        }
        println!(
            "  {:<40} value={:#010x} size={:>6} kind={:?} scope={:?} section={:?}",
            name,
            sym.address(),
            sym.size(),
            sym.kind(),
            sym.scope(),
            sym.section(),
        );
    }

    println!("\nRELOCATIONS");
    let symbols: Vec<_> = elf.symbols().collect();
    for section in elf.sections() {
        let relocs: Vec<_> = section.relocations().collect();
        if relocs.is_empty() {
            continue;
        }
        println!("  in {}:", section.name().unwrap_or("<?>"));
        for (offset, rel) in relocs {
            let target_name = match rel.target() {
                object::RelocationTarget::Symbol(idx) => symbols
                    .iter()
                    .find(|s| s.index() == idx)
                    .and_then(|s| s.name().ok())
                    .unwrap_or("<?>")
                    .to_string(),
                other => format!("{:?}", other),
            };
            let flags = match rel.flags() {
                object::RelocationFlags::Elf { r_type } => {
                    format!("elf_type={}", aarch64_reloc_name(r_type))
                }
                other => format!("{:?}", other),
            };
            println!(
                "    {:#010x} -> {:<40} addend={:+#x} {}",
                offset,
                target_name,
                rel.addend(),
                flags
            );
        }
    }
    Ok(())
}

fn aarch64_reloc_name(t: u32) -> String {
    use object::elf::*;
    let name = match t {
        R_AARCH64_NONE => "R_AARCH64_NONE",
        R_AARCH64_ABS64 => "R_AARCH64_ABS64",
        R_AARCH64_ABS32 => "R_AARCH64_ABS32",
        R_AARCH64_ABS16 => "R_AARCH64_ABS16",
        R_AARCH64_PREL64 => "R_AARCH64_PREL64",
        R_AARCH64_PREL32 => "R_AARCH64_PREL32",
        R_AARCH64_CALL26 => "R_AARCH64_CALL26",
        R_AARCH64_JUMP26 => "R_AARCH64_JUMP26",
        R_AARCH64_ADR_PREL_PG_HI21 => "R_AARCH64_ADR_PREL_PG_HI21",
        R_AARCH64_ADD_ABS_LO12_NC => "R_AARCH64_ADD_ABS_LO12_NC",
        R_AARCH64_LDST8_ABS_LO12_NC => "R_AARCH64_LDST8_ABS_LO12_NC",
        R_AARCH64_LDST16_ABS_LO12_NC => "R_AARCH64_LDST16_ABS_LO12_NC",
        R_AARCH64_LDST32_ABS_LO12_NC => "R_AARCH64_LDST32_ABS_LO12_NC",
        R_AARCH64_LDST64_ABS_LO12_NC => "R_AARCH64_LDST64_ABS_LO12_NC",
        R_AARCH64_LDST128_ABS_LO12_NC => "R_AARCH64_LDST128_ABS_LO12_NC",
        R_AARCH64_ADR_GOT_PAGE => "R_AARCH64_ADR_GOT_PAGE",
        R_AARCH64_LD64_GOT_LO12_NC => "R_AARCH64_LD64_GOT_LO12_NC",
        _ => return format!("R_AARCH64_{t}"),
    };
    name.to_string()
}

fn open_binary<'a>(mmap: &'a memmap2::Mmap, path: &Path) -> Result<delink_core::Binary<'a>> {
    delink_core::Binary::load(&mmap[..])
        .with_context(|| format!("failed to load {}", path.display()))
}

fn mmap_file(path: &Path) -> Result<memmap2::Mmap> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    Ok(unsafe { memmap2::Mmap::map(&file)? })
}

fn cmd_inspect(path: &Path) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let report = delink_core::inspect::inspect(&binary)?;
    print!("{}", delink_core::inspect::format_text(&report));
    Ok(())
}

fn cmd_emit(
    path: &Path,
    cu_needle: &str,
    output: &Path,
    comdat: bool,
    dwarf: bool,
    per_function_sections: bool,
) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    let cu = delink_emit::find_cu(&idx.units, cu_needle)
        .ok_or_else(|| anyhow!("no CU matches suffix '{}'", cu_needle))?;

    tracing::info!(
        "emitting CU '{}' ({} functions, {} ranges)",
        cu.name,
        cu.functions.len(),
        cu.ranges.len()
    );

    let symbols = delink_core::symbols::GlobalSymbols::build(&binary, &idx)?;
    tracing::info!(
        "resolved {} functions across all CUs, {} PLT stubs",
        symbols.functions.len(),
        symbols.plt.len()
    );

    let stats = delink_emit::emit_cu(
        &binary,
        delink_emit::EmitOptions {
            cu,
            symbols: &symbols,
            comdat,
            dwarf,
            per_function_sections,
        },
        output,
    )?;
    println!(
        "wrote {}\n  .text: {} bytes ({} insns)\n  symbols: {} local, {} undef\n  relocs: {} emitted\n  calls: {} unresolved\n  adrp: {} seen, {} paired, {} unresolved\n  ranges coalesced: {}",
        output.display(),
        stats.text_bytes,
        stats.instructions,
        stats.local_symbols,
        stats.undef_symbols,
        stats.relocations,
        stats.unresolved_calls,
        stats.adrp_seen,
        stats.adrp_paired,
        stats.adrp_unresolved,
        stats.ranges_coalesced,
    );
    Ok(())
}

fn cmd_list_cus(path: &Path, contains: &str, limit: usize) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    let mut rows: Vec<_> = idx
        .units
        .iter()
        .filter(|u| u.name.contains(contains))
        .map(|u| {
            let bytes: u64 = u.ranges.iter().map(|r| r.end - r.start).sum();
            (bytes, u.functions.len(), u.name.clone())
        })
        .collect();
    rows.sort_by_key(|(b, _, _)| *b);
    println!("{:>10} {:>6}  name", "bytes", "funcs");
    for (bytes, funcs, name) in rows.iter().take(limit) {
        println!("{:>10} {:>6}  {}", bytes, funcs, name);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PE + PDB subcommands
// ---------------------------------------------------------------------------

fn load_pe_context(exe_path: &Path, pdb_path: &Path) -> Result<delink_pe::PeContext> {
    let exe_data =
        std::fs::read(exe_path).with_context(|| format!("read {}", exe_path.display()))?;
    let pdb_data =
        std::fs::read(pdb_path).with_context(|| format!("read {}", pdb_path.display()))?;
    tracing::info!(
        "loaded PE ({} bytes) + PDB ({} bytes)",
        exe_data.len(),
        pdb_data.len()
    );
    delink_pe::load_pe_and_pdb(&exe_data, &pdb_data)
        .with_context(|| format!("load {} + {}", exe_path.display(), pdb_path.display()))
}

fn cmd_pe_inspect(exe_path: &Path, pdb_path: &Path) -> Result<()> {
    let pe = load_pe_context(exe_path, pdb_path)?;

    println!("PE sections:");
    println!("  {:<16} {:>16} {:>12}  flags", "name", "VA", "size");
    for s in &pe.sections {
        println!(
            "  {:<16} {:#016x} {:>12}  0x{:08x}",
            s.name, s.va, s.virtual_size, s.characteristics
        );
    }

    println!("\nBase relocations: {} entries", pe.base_relocations.len());
    let dir64 = pe
        .base_relocations
        .iter()
        .filter(|r| matches!(r.kind, delink_pe::BaseRelocKind::Dir64))
        .count();
    println!(
        "  DIR64: {}  other: {}",
        dir64,
        pe.base_relocations.len() - dir64
    );

    println!("\nImports: {} IAT entries", pe.imports.len());

    println!("\nPDB modules (CUs): {}", pe.cu_index.units.len());
    let total_funcs: usize = pe.cu_index.units.iter().map(|u| u.functions.len()).sum();
    println!("  total functions: {}", total_funcs);

    Ok(())
}

fn cmd_pe_list_cus(exe_path: &Path, pdb_path: &Path, contains: &str, limit: usize) -> Result<()> {
    let pe = load_pe_context(exe_path, pdb_path)?;

    let mut rows: Vec<_> = pe
        .cu_index
        .units
        .iter()
        .filter(|u| u.name.contains(contains))
        .map(|u| (u.text_size(), u.functions.len(), u.name.clone()))
        .collect();
    rows.sort_by_key(|(b, _, _)| *b);

    println!("{:>10} {:>6}  name", "text bytes", "funcs");
    for (bytes, funcs, name) in rows.iter().take(limit) {
        println!("{:>10} {:>6}  {}", bytes, funcs, name);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mach-O subcommands
// ---------------------------------------------------------------------------

fn load_macho_context(path: &Path) -> Result<delink_macho::MachoContext> {
    let data =
        std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    tracing::info!("loaded Mach-O ({} bytes)", data.len());
    delink_macho::load_macho(&data)
        .with_context(|| format!("load {}", path.display()))
}

fn cmd_macho_inspect(path: &Path) -> Result<()> {
    let ctx = load_macho_context(path)?;

    println!("Mach-O  arch={:?}", ctx.arch);
    println!("\nSECTIONS");
    println!("  {:<20} {:<12} {:>16} {:>12}  flags", "segment", "name", "addr", "size");
    for s in &ctx.sections {
        println!(
            "  {:<20} {:<12} {:#016x} {:>12}  0x{:08x}",
            s.segment, s.name, s.addr, s.size, s.flags
        );
    }

    println!("\nDWARF compilation units: {}", ctx.cu_index.units.len());
    let total_funcs: usize = ctx.cu_index.units.iter().map(|u| u.functions.len()).sum();
    println!("  total functions: {}", total_funcs);

    Ok(())
}

fn cmd_macho_list_cus(path: &Path, contains: &str, limit: usize) -> Result<()> {
    let ctx = load_macho_context(path)?;

    let mut rows: Vec<_> = ctx
        .cu_index
        .units
        .iter()
        .filter(|u| u.name.contains(contains))
        .map(|u| (u.text_size(), u.functions.len(), u.name.clone()))
        .collect();
    rows.sort_by_key(|(b, _, _)| *b);

    println!("{:>10} {:>6}  name", "text bytes", "funcs");
    for (bytes, funcs, name) in rows.iter().take(limit) {
        println!("{:>10} {:>6}  {}", bytes, funcs, name);
    }
    Ok(())
}

fn cmd_macho_split(path: &Path, outdir: &Path) -> Result<()> {
    let ctx = load_macho_context(path)?;

    tracing::info!(
        "splitting {} CUs (with functions) in parallel",
        ctx.cu_index
            .units
            .iter()
            .filter(|u| u.functions.iter().any(|f| f.size > 0))
            .count()
    );

    let outcomes = delink_macho::emit::split_all_macho(&ctx, outdir)?;

    let shared = outdir.join("__shared_data.o");
    tracing::info!("emitting shared data → {}", shared.display());
    let shared_stats = delink_macho::emit::emit_macho_shared(&ctx, &shared)?;

    let mut total = delink_macho::EmitStats::default();
    let mut failures = 0usize;
    for o in &outcomes {
        match &o.result {
            Ok(s) => {
                total.text_bytes += s.text_bytes;
                total.local_symbols += s.local_symbols;
                total.undef_symbols += s.undef_symbols;
                total.relocations += s.relocations;
                total.unresolved_calls += s.unresolved_calls;
                total.instructions += s.instructions;
            }
            Err(e) => {
                failures += 1;
                tracing::warn!(cu = %o.cu_name, error = %e, "emit failed");
            }
        }
    }

    println!(
        "macho-split complete: {} CUs ({} failed)\n  {} bytes .text, {} instructions\n  {} local + {} undef symbols\n  {} relocs ({} unresolved calls)\n  shared: data={} const={} bss={}",
        outcomes.len().saturating_sub(failures),
        failures,
        total.text_bytes,
        total.instructions,
        total.local_symbols,
        total.undef_symbols,
        total.relocations,
        total.unresolved_calls,
        shared_stats.data_bytes,
        shared_stats.const_bytes,
        shared_stats.bss_bytes,
    );
    Ok(())
}

fn cmd_pe_split(exe_path: &Path, pdb_path: &Path, outdir: &Path) -> Result<()> {
    let pe = load_pe_context(exe_path, pdb_path)?;

    tracing::info!(
        "splitting {} CUs (modules with functions) in parallel",
        pe.cu_index
            .units
            .iter()
            .filter(|u| u.functions.iter().any(|f| f.size > 0))
            .count()
    );

    let outcomes = delink_pe::emit::split_all_pe(&pe, outdir)?;

    let shared = outdir.join("__shared_data.obj");
    tracing::info!("emitting shared data → {}", shared.display());
    let shared_stats = delink_pe::emit::emit_pe_shared(&pe, &shared)?;

    let mut total = delink_pe::emit::EmitStats::default();
    let mut failures = 0usize;
    for o in &outcomes {
        match &o.result {
            Ok(s) => {
                total.text_bytes += s.text_bytes;
                total.local_symbols += s.local_symbols;
                total.undef_symbols += s.undef_symbols;
                total.relocations += s.relocations;
                total.unresolved_calls += s.unresolved_calls;
                total.instructions += s.instructions;
            }
            Err(e) => {
                failures += 1;
                tracing::warn!(cu = %o.cu_name, error = %e, "emit failed");
            }
        }
    }

    println!(
        "pe-split complete: {} modules ({} failed)\n  {} bytes .text, {} instructions\n  {} local + {} undef symbols\n  {} relocs ({} unresolved calls)\n  shared: rdata={} data={} bss={} ({} ADDR64 relocs)",
        outcomes.len().saturating_sub(failures),
        failures,
        total.text_bytes,
        total.instructions,
        total.local_symbols,
        total.undef_symbols,
        total.relocations,
        total.unresolved_calls,
        shared_stats.rdata_bytes,
        shared_stats.data_bytes,
        shared_stats.bss_bytes,
        shared_stats.addr64_relocs,
    );
    Ok(())
}
