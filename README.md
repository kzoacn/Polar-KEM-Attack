# Polar-KEM-Attack

Total break of the Polar-KEM NICCS round-1 reference implementation: the shared secret of any honestly generated ciphertext is recovered from the public key and ciphertext alone.

See [REPORT.md](REPORT.md). PoC (self-contained, reads the unmodified official KAT files beside it):

```sh
python3 poc.py    # 30/30 vectors recovered
```
