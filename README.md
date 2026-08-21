# CHIP-8

CHIP-8 repository for ImHex stuff like patterns or disassemblers.

This project uses Octo, the high-level pseudo-assembler syntax for CHIP-8, because it has the most examples available.
The other one is Chipper from 90s. It is not quite popular today and it is difficult to find games with source code using this syntax.

## Development

### Requirements

- mise 2026.8.8+
- prek 0.4.14+

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
