# firmina

A lightweight command-line tool for creating digital signatures using **CAdES** (`.p7m` / `.p7s`) and **PAdES** (`.pdf`) with **InfoCert bit4id** smart cards.

Internally, Firmina uses OpenSSL (which must already be installed on the system) and bundles the libraries required to interact with PKCS#11 devices, including the proprietary drivers used by InfoCert's bit4id signing tokens.

The binary can be installed into `~/.local/bin` so it is available from your `PATH` and can easily be used in scripts, terminal workflows, and automation.

## Why?

Digital signature support on Linux has traditionally been poor. Existing solutions are often heavyweight, difficult to install, and focused on fulfilling a minimum Linux support requirement rather than providing a pleasant user experience.

Firmina aims to provide a simple, scriptable, Unix-friendly alternative.

## Features

* Sign arbitrary files using **CAdES**
  * Attached signatures (`.p7m`)
  * Detached signatures (`.p7s`)
* Co-sign existing CAdES signatures
  * Attached (`.p7m`)
  * Detached (`.p7s`)
* Sign PDF documents using **PAdES**
* Extract the encapsulated content of attached CAdES signatures (`.p7m`)
* PKCS#11 smart card support
* Interactive PIN prompt
* PIN retrieval via environment variable
* Designed to integrate cleanly with shell scripts and automation

## Installation

Firmina requires:

* OpenSSL
* A supported bit4id PKCS#11 token
* The corresponding PKCS#11 libraries

Download the binary and place it in a directory included in your `PATH`, for example:

```sh
mkdir -p ~/.local/bin
cp firmina ~/.local/bin/
```

## Usage

Firmina exposes a self-documenting command-line interface.

To discover all available commands, options, and examples, use:

```sh
firmina --help
```

or command-specific help pages:

```sh
firmina sign --help
firmina extract --help
```

The help output is designed to fully document the current CLI and should always be considered the authoritative reference.

## Signing

Firmina can automatically determine how an input file should be handled:

| Input          | Default behavior                                     |
| -------------- | ---------------------------------------------------- |
| `.pdf`         | Sign using PAdES                                     |
| `.p7m`         | Add a signature to an attached CAdES signature       |
| `.p7s`         | Add a signature to a detached CAdES signature        |
| Any other file | Sign as a generic file using attached CAdES (`.p7m`) |

Automatic detection can be overridden explicitly when needed.

### Detached signatures

For CAdES signatures, the output format can be chosen explicitly.

By default, Firmina produces attached signatures (`.p7m`).

Detached signatures (`.p7s`) can also be generated. When working with an existing detached signature, the original content must be provided so the signature can be interpreted correctly.

### PIN handling

The PIN may be supplied interactively or through the `FIRMINA_PIN` environment variable:

```sh
export FIRMINA_PIN=12345678
```

If no PIN is provided, Firmina will prompt for it securely.

## Extracting files

Firmina can extract the original content embedded within an attached CAdES signature (`.p7m`).

When the output path is omitted, a sensible default is chosen automatically.

## Philosophy

Firmina prioritizes:

* Simplicity
* Scriptability
* Predictable behavior
* Minimal external dependencies
* Good Linux support

The goal is to make digital signatures on Linux feel like a normal command-line workflow rather than a heavyweight desktop application.

## AI Disclaimer

This readme was generated using an LLM, but all the code was handwritten. AI was used for research about libraries, rust patterns and overall improvements but I never gave access to the codebase to any agent, I just chatted with an LLM to ask some things and I always typed and checked my code manually. This project is a learning opportunity and it wouldn't make sense to outsource critical thinking to an LLM.
