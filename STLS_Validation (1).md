# Seven scenario experiment validation

The delivered version passed **23 tests** and then ran all seven requested scenarios with **one actual 60-second network window and one independent 60-second key-generation window per scenario**. The source hashes in the supplied run manifest match the delivered modules. This is one repetition for functional validation, not the 20-repetition publication study.

The tests cover all seven actual TLS configurations and an authenticated 32,769-byte payload; selected curve and authenticated certificate-size checks; wrong ServerHello group rejection; bilateral UDP and QUIC packet accounting; ephemeral and STLS key-generation counters; capacity-batch reconciliation; fixed-window/aggregate event consistency; malformed, truncated and tampered messages; state rotation; replay; lost SH/Finished/ACK recovery; untrusted certificates; a silent server; and resuming without duplicate results.

Every networking and capacity window below has a fixed **60-second denominator**. The key-capacity columns are from the independent generation window, not the network window.

| Scenario | Completed session-ready handshakes | Client UDP sent | Client UDP received | Capacity operations | Generated pairs | Generated AES keys | Network failures |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| quic_tls_ecdhe_secp256r1 | 13972 | 56037 | 42236 | 4272641 | 4272641 | 0 | 0 |
| quic_tls_rsa2048 | 13259 | 66448 | 53302 | 1284 | 1284 | 0 | 0 |
| quic_tls_ecdhe_secp384r1 | 9884 | 39675 | 30193 | 365671 | 365671 | 0 | 0 |
| quic_stls | 9989 | 59189 | 48858 | 32109624 | 0 | 64219248 | 0 |
| quic_tls_rsa3072 | 11390 | 57077 | 45790 | 369 | 369 | 0 | 0 |
| quic_tls_rsa4096 | 9942 | 49842 | 39966 | 132 | 132 | 0 | 0 |
| quic_tls_ecdhe_secp521r1 | 11126 | 44628 | 33712 | 408591 | 408591 | 0 | 0 |

All observed groups and RSA moduli matched the scenario settings. Post-run checks reconciled attempt counts, four stage rows per attempt, client packet/byte aggregates with per-connection counters, key-capacity counts with batches, and server key counts with successful client completions. No counted readiness timestamp exceeded its window; TLS resumption was false; no unhandled connection-future warning appeared. Generated initial secrets were absent from the performance CSVs. Provisioning secrets and private PEM files are excluded from the downloadable examples.

The network CSV separately includes actually generated endpoint ephemeral pairs and server STLS renewal keys. Long-term RSA certificate keys were generated before the network window and reused. TLS 1.3 RSA scenarios use RSA authentication with secp256r1 exchange; the ECDHE scenarios keep the same ECDSA P-256 certificate and explicitly vary the exchange group. QUIC/STLS includes its underlying TLS bootstrap. Packet counts describe the repeated-handshake workload, not maximum link capacity.

These observations were collected in a shared Linux execution environment. They are not measurements on your i7 laptop or on the five commercial IoT devices, and a single pass does not establish a statistically reliable ranking. Native Windows execution was not available. Use the supplied Windows instructions to collect the actual reference-laptop study, optionally with `--runs 20`, under stable background load and power policy. Different testbeds will produce different counts.

`comparison.csv`, `runs.csv`, `key_generation.csv`, their summary CSVs, the test output and raw CSV/JSON evidence are included in the ZIP. Runtime and software versions are in `validation_example/manifest.json`. Fresh test credentials are created when you run the code.
