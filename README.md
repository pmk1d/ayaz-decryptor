# Ayaz Decryptor

A decryptor for files encrypted by a compatible LockBit 3 / AyazL0CKER variant.
Recovery requires a metadata keystream profile for the matching group of files.
The program checks that the profile applies and saves the result to a new file.

## Installation and usage

Requires Python 3.10+ and Linux or macOS.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .

ayaz-decryptor decrypt encrypted.bin \
  --profile profile.json \
  --original-name document.txt \
  --output recovered.txt
```

If a C compiler is available, installation builds a native Salsa20 accelerator.
Otherwise, the slower Python implementation is used. The decryptor requires no
third-party runtime libraries. An NVIDIA GPU is needed only for the separate
[CUDA search tool](cuda/README.md).

## Important details

- The profile contains `key_blob_sha256`, `stream_hex`, and `known_mask_hex`.
  The mask uses `00` for unknown bytes and `01` for known bytes.
  `stream_hex` is the metadata keystream, not the file's 64-byte Salsa20 state.
  A profile for a different group or an incomplete content key stops decryption.
- `--original-name` is the original filename before encryption, without a path.
- The input file and any existing output file are never overwritten.
- To verify the recovered content, add `--expected-sha256 HEX` with a known hash
  of the original. Without it, the report explicitly marks content integrity as
  unverified.
- Profiles and keys must be obtained separately: there is no master key for all
  affected files. Input formats are described in [docs/FORMATS.md](docs/FORMATS.md).

## Try it without your own files

```sh
python examples/make_demo.py demo-output
ayaz-decryptor decrypt demo-output/encrypted.bin \
  --profile demo-output/profile.json --original-name a.txt \
  --output demo-output/recovered.txt
```

The example is entirely synthetic. Two more commands work with ZIP archives of
encrypted and original file pairs:

```sh
ayaz-decryptor analyze demo-output/pairs.zip
ayaz-decryptor verify demo-output/pairs.zip --profile demo-output/profile.json
```

## Development

```sh
python -m pip install -e .
python -m unittest discover -s tests -t .
python benchmarks/benchmark.py
make -C cuda test
python -m unittest discover -s cuda -p 'test_*.py'
```

Licensed under [MIT](LICENSE). The research this project builds on is listed
in [NOTICE.md](NOTICE.md).
