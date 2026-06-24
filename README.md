# delink [![Build Status]][actions] [![Discord Badge]][discord]

[Build Status]: https://github.com/HaydnTrigg/delink/actions/workflows/build.yaml/badge.svg
[actions]: https://github.com/HaydnTrigg/delink/actions
[Discord Badge]: https://img.shields.io/badge/Discord-PC/Xbox%20Decompilation-blue?color=%237289DA&logo=discord&logoColor=%23FFFFFF
[discord]: https://discord.gg/v3xcYgHvNZ

A splitting tool for decompilation projects.

## Supported Formats:
- Shared Object (.so) files with DWARF
- Mach-O STABS and SYMTAB
- Windows PE with PDB's (.exe/.pdb).
- Any binary IDA can analyse, via the [IDA import](#ida-import) workflow.

## IDA import

When you don't have debug info but do have an IDA database, you can split using
IDA's analysis. There are two pieces, decoupled by a JSON file so delink never
has to link against IDA:

1. **Export** (inside IDA 9.x). Run [`crates/delink-ida/ida_export.py`](crates/delink-ida/ida_export.py)
   to write a small, human-readable JSON describing the architecture/segment
   layout, every function (boundaries + flags), the full address → name map, and
   the relocations IDA knows (its fixup table **and** offset-typed operands —
   the latter being the only relocation record for images with no `.reloc`,
   e.g. EXEs). The export carries **no bytes**:

   ```shell
   # headless (idat64.exe for a 64-bit database)
   "idat.exe" -A -S"crates\delink-ida\ida_export.py delink.ida.json" database.idb
   ```
   or, interactively, File → Script file… and pick the script.

2. **Import + split** (delink). Pass the JSON **and the original binary** (the
   bytes and the PE `.reloc` table come from there):

   ```shell
   delink ida-split delink.ida.json binary.exe -o ./output
   ```

   For **x86 / x86-64** targets delink disassembles each function with iced-x86
   to recover rel32 call/jump relocations, and combines IDA's relocations with
   the binary's `.reloc` table for absolute pointers, resolving every target
   through the exported name map. Output is COFF `.obj` for PE inputs (use
   `--elf` for ELF `.o`).

   As with the Mach-O splitter, the first run writes an editable `idapro.json`
   grouping (`{ "<obj>": { "<sym>": {address, size, scope} } }`) into the output
   directory. Edit it to group symbols into objects (and rename keys to rename
   files), then re-run with `--idapro ./out/idapro.json`.

## Building

Install Rust via [rustup](https://rustup.rs).

```shell
git clone https://github.com/HaydnTrigg/delink.git
cd delink
cargo run --release
```

Or install directly with cargo:

```shell
cargo install --locked --git https://github.com/HaydnTrigg/delink.git delink
```

Binaries will be installed to `~/.cargo/bin` as `delink`.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.