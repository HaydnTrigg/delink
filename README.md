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