# Benchmark runner

Run the default measured ML-KEM-768 and ML-DSA-65 workload with a real message file:

```bash
OQS_INSTALL_PATH="$PWD/.native/liboqs" uv run --locked --extra benchmark pqclab benchmark \
  --iterations 100 \
  --message-file ./path/to/real-message.bin \
  --output-dir ./benchmark-results
```

The benchmark measures key generation, KEM encapsulation/decapsulation, signature key generation/signing/verification, and records latency, operations/second, message throughput, public/secret key sizes, ciphertext size and signature size. It executes real native cryptographic operations and self-checks the resulting shared secret and signature; it never inserts synthetic timing values.

Each invocation creates a unique run directory containing:
- `results.json`: environment, parameters and raw samples
- `results.csv`: one row per operation with raw latency samples
- `latency.png`: median latency chart

The user supplies the message file and iteration count explicitly. Benchmark output contains measurements and size metadata only, never keys or message contents. The benchmark extra is optional and pins Matplotlib. Results are hardware-, OS-, compiler- and load-dependent; compare runs only with their environment metadata.
