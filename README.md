# CHIP-8

CHIP-8 repository for ImHex stuff like patterns or disassemblers.

This project uses Octo, the high-level pseudo-assembler syntax for CHIP-8, because it has the most examples available.
The other one is Chipper from 90s. It is not quite popular today and it is difficult to find games with source code using this syntax.

## Features

### ImHex disassembler plugin

This is a work-in-progress static analysis disassembler plugin that can be integrated in the ImHex.

At this moment, automated builds are disabled as ImHex is going through a lot of good changes and I don't consider this plugin to be finished.

It already supports:

- CHIP-8 and SUPER-CHIP opcodes (XO-CHIP is WIP) - the most popular variants
- recognizing instructions and sprite data
- describing jump points with labels and separating them from sprite (data) labels
- static analysis more errorprone than the original disasm included in Octo

### ImHex custom (JSON) disassembler

As with any simple, bit masking disassembler, it provides a generic overview of the binary but can incorrectly show sprite data as instructions.

The advantage is that this is a JSON file that can be used anywhere without an ImHex runtime.

It lives in the [custom directory](./custom/disassemblers/chip-8.json).

## Development

### Requirements

- mise 2026.10.4+
- prek 0.5.5+

### Setup tooling

You can install all needed tooling using mise:

```shell
mise install
```

### Setup pre-commit hooks

You can install hooks to automatically run the validation checks:

```shell
prek install
```

### Basic workflow

```bash
# Run pre-commit checks for changed files
prek

# Run all pre-commit checks
prek --all-files
```

## License

This project is licensed under the terms of the [European Union Public License v1.2](https://github.com/Omikorin/chip8/blob/main/LICENSE).

---

<p align="center">Made with 🩵 by <a href="https://omikor.in" target="_blank">Michał Korczak</a></p>

---
