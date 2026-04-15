# delink [![Build Status]][actions]

[Build Status]: https://github.com/HaydnTrigg/delink/actions/workflows/build.yaml/badge.svg
[actions]: https://github.com/HaydnTrigg/delink/actions

A splitting tool for decompilation projects for Shared Object (.so) files with DWARF and Windows Executables with PDB's (.exe/.pdb).

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