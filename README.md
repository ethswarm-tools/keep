# keep

An encrypted secrets/notes vault synced over [Swarm](https://www.ethswarm.org/).
Your key/value pairs are encrypted **client-side** (ChaCha20-Poly1305) —
only ciphertext ever reaches Swarm — and made mutable behind a feed, so
the vault follows you across machines.

Built on the [scout](https://github.com/ethswarm-tools/scout) library
(`swarm-scout`).

> Published on crates.io as **`swarm-keep`**; the binary is `keep`.

## Install

```sh
cargo install swarm-keep      # provides the `keep` command
```

## Usage

```sh
keep init --stamp <batch>                 # create a vault (writes ~/.keep/keep.json)
keep set api-token s3cr3t --stamp <batch> # store a secret
keep get api-token                        # -> s3cr3t   (read; no stamp needed)
keep list                                 # list keys
keep rm  api-token --stamp <batch>        # remove a key
```

Uploads (`init` / `set` / `rm`) go to `--node` / `$BEE_NODE` (defaults to
`--gateway`) and need `--stamp` / `$BEE_STAMP`. Reads (`get` / `list`) use
`--gateway` / `$BEE_GATEWAY` only.

## How it works

The vault is a JSON map encrypted with ChaCha20-Poly1305 under a key
derived from a locally-stored secret (`~/.keep/keep.json`); the ciphertext
is uploaded to Swarm and a feed points at the latest version. **The
config file is the only thing that can decrypt your vault** — copy it to
another machine to access the same vault; lose it and the data is
unrecoverable (by design). Nothing readable is ever stored on Swarm.

## Status

`init` / `set` / `get` / `list` / `rm`, verified end-to-end against a live
Bee node (2.7.2): the on-chain blob is ciphertext (no plaintext leaks),
and round-trips decrypt correctly.

## License

MIT


---
📖 Part of the **[scout toolkit](https://ethswarm-tools.github.io/scout/)** (scout · stash · perch · keep).
