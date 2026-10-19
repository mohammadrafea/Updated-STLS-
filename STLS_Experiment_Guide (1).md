# One minute QUIC comparison across seven scenarios

This package runs the seven requested client/server scenarios and writes CSV results for completed handshakes, sent and received packets, key generation, timings, memory and CPU use. The default is **one repetition per scenario**, using **60 seconds for networking and a separate 60 seconds for key-generation capacity**. Total timed execution is approximately **14 minutes**, plus provisioning, warm-up and cooldown.

The two windows answer different questions. The network window measures real repeated QUIC connections, including the keys actually generated during those connections. The key-generation window measures how many fresh RSA pairs, EC pairs or STLS credential bundles can be generated in isolation in one minute. This avoids adding long-term RSA key/certificate generation to every TLS handshake, which conventional TLS does not do.

## The seven scenarios

| Scenario ID | Server certificate and signature key | Actual ephemeral TLS group | Additional STLS handshake |
| --- | --- | --- | --- |
| `quic_stls` | ECDSA P-256 | secp256r1 | Yes, dual AES-256-GCM, HMAC and rolling credentials |
| `quic_tls_rsa4096` | RSA 4096 bits | secp256r1 | No |
| `quic_tls_rsa3072` | RSA 3072 bits | secp256r1 | No |
| `quic_tls_rsa2048` | RSA 2048 bits | secp256r1 | No |
| `quic_tls_ecdhe_secp256r1` | ECDSA P-256 | secp256r1 | No |
| `quic_tls_ecdhe_secp384r1` | ECDSA P-256 | secp384r1 | No |
| `quic_tls_ecdhe_secp521r1` | ECDSA P-256 | secp521r1 | No |

TLS 1.3 uses RSA for authentication signatures, not RSA key transport. Therefore the RSA scenarios retain a fixed secp256r1 ephemeral exchange and vary the RSA certificate key size. The ECDHE scenarios retain the same ECDSA P-256 certificate and vary only the exchange curve. An ECDSA certificate curve and an ECDHE exchange curve are independent choices. All seven use the same AES-256-GCM/SHA-384 TLS cipher suite, fresh connections and no session tickets or 0-RTT.

**QUIC/STLS retains the underlying aioquic QUIC/TLS handshake.** It then performs the custom STLS control-stream handshake. The code measures and labels both costs; it does not claim to remove TLS from standardized QUIC. Consequently this profile can take more time and packets than the TLS-only P-256 profile. No result is forced to reproduce the manuscript's historical latency or approximately 244-byte size.

`tls_profile.py` is a small, version-checked adapter for aioquic 1.2.0, which has no public supported-groups setting. It selects exactly one curve, examines the actual ServerHello group, and retains the library's original certificate, signature and Finished checks. The client also verifies the authenticated certificate's key size. A mismatch or unsupported curve fails the test instead of falling back to another curve. The private APIs used by this adapter are documented and covered by tests; do not upgrade aioquic without revalidation.

## Install and run on Windows

Extract `STLS_Automated_Experiment.zip` into a short path such as `C:\STLS` to avoid Windows path-length limits, open PowerShell in the extracted project folder and use Python 3.12. Python 3.11 or newer is required.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_experiment.py
```

No second terminal, manual certificate generation, R installation or server launch is required. The runner starts and stops the server and client automatically for each scenario. Internet access is needed for dependency installation, while the default network experiment uses localhost.

A short installation check runs the same algorithms with two-second windows:

```powershell
.\.venv\Scripts\python.exe run_experiment.py --seconds 2 --warmup 1 --keygen-warmup 0 --cooldown 0
```

The full requested experiment is:

```powershell
.\.venv\Scripts\python.exe run_experiment.py --seconds 60 --runs 1
```

For Phil's recommended 20 independent repetitions per scenario:

```powershell
.\.venv\Scripts\python.exe run_experiment.py --seconds 60 --runs 20
```

With both windows enabled, 20 repetitions take 280 minutes of timed execution, plus setup and warm-up. Each repetition uses a randomized block containing all seven scenarios; the schedule seed is recorded. Run under stable power, thermal conditions and background load when collecting paper results.

Linux/macOS equivalents:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python run_experiment.py
```

The direct versions used for the supplied validation are in `requirements-tested.txt`; every new suite records its actual dependency versions and source hashes.

## Choose a subset or one measurement

Only one scenario:

```powershell
.\.venv\Scripts\python.exe run_experiment.py --approaches quic_tls_rsa4096
```

Only the seven one-minute client/server networking windows, approximately seven minutes:

```powershell
.\.venv\Scripts\python.exe run_experiment.py --benchmarks network
```

This still records the ECDHE pairs generated by the real TLS handshake and the fresh STLS keys generated during networking. It does not measure standalone RSA key-generation capacity.

Only standalone key-generation capacity, approximately seven minutes:

```powershell
.\.venv\Scripts\python.exe run_experiment.py --benchmarks keys
```

The legacy IDs `quic_tls_rsa`, `quic_tls_ecdsa` and `tcp_stls` remain available for earlier workflows but are excluded from the default seven. Explicit scenario IDs now select RSA size; the old global `--rsa-bits` runner option is no longer used.

## CSVs to open first

Each suite gets a new timestamped directory under `results/minute_runs`. CSVs use UTF-8, headers and explicit units. They can be opened directly in Excel, Python or R.

| File | Row unit | Main purpose |
| --- | --- | --- |
| `comparison.csv` | One scenario and repetition | Joins the network and independent key-generation windows with their durations labelled separately |
| `runs.csv` | One network window | Complete handshakes, endpoint packets/bytes, keys generated during networking, timings, CPU and memory |
| `key_generation.csv` | One isolated key-generation window | Generation operations, RSA/EC pairs, AES keys, SIDs, failed/censored work and normalized rates |
| `summary.csv` | One network metric and scenario | Across-repetition mean, SD, median, range and bootstrap interval |
| `key_generation_summary.csv` | One generation metric and scenario | Across-repetition key-capacity statistics |
| `DEVICE_handshakes.csv` | One network window | Per-device version of `runs.csv`, matching one-run-per-line reporting |
| `DEVICE_stages.csv` | One stage of one attempt | Three nonoverlapping timing stages plus the total |

`comparison.csv` contains both packet definitions: `*_udp_datagrams_*` are socket datagrams and `*_quic_packets_*` are QUIC packets reported by the library. It also contains network-window ephemeral pairs and STLS keys, independently measured key-generation operations/pairs/symmetric keys, handshake count and mean session-ready latency. A blank key-capacity cell means that window was not run; it does not mean zero.

For a 60-second window, the completed count is the observed per-minute count. For a short check, a `*_per_minute` field is a normalized rate, not an observed one-minute result. Do not publish the short smoke-run counts as one-minute observations.

## What one key means

| Measurement | One completed operation | Count fields |
| --- | --- | --- |
| Isolated RSA capacity | Generate one fresh private/public pair at the selected modulus size | `generated_key_pairs` |
| Isolated ECDHE capacity | Generate one fresh EC private/public pair on the selected curve | `generated_key_pairs` |
| Isolated STLS capacity | Generate two independent AES-256 keys and a fresh 32-byte SID, using the same `Credentials.generate` function as the server | `generated_symmetric_keys = 2 × operations`; `generated_sids = operations` |
| Networking, TLS | Observe the real ephemeral key-pair generation in each endpoint's TLS context | `client_ephemeral_key_pairs_generated`, `server_ephemeral_key_pairs_generated` |
| Networking, STLS | Observe server generation of next-epoch credential bundles; cache retries do not generate another bundle | `server_stls_key_bundles_generated`, `server_stls_symmetric_keys_generated` |

A key pair is reported as one pair, not silently equated to one symmetric key. Use the operation and key-type columns when comparing counts. Isolated EC capacity does not include an ECDH shared-secret computation; the real network handshake does perform that computation. Isolated RSA capacity does not include certificate construction or signing. Preparation costs and sizes are recorded separately in `preparation.csv` before networking starts.

Long-term certificate keys are reused throughout a network window. `long_term_certificate_key_pairs_generated_in_window` is therefore zero. TLS ephemeral generation counts include work for attempts that later fail or are censored, provided the generation callback completed within the window. The client and server can have different counts near the boundary. Network pair counts are observed at completed TLS hello-processing callbacks; in-flight work not yet observed by its callback is excluded. STLS generation counts can exceed twice the client-completed handshake count because a server may have generated credentials for an unfinished final exchange. `client_stls_symmetric_keys_installed` separately records two keys for each client-verified STLS completion.

These counters intentionally do not count every intermediate TLS/HKDF traffic secret as a new independent key-generation operation. Purpose-separated STLS working keys use HKDF-SHA256, while renewed STLS credentials use `os.urandom`. RSA and EC generation use the cryptography backend's secure random source. This portable implementation does not read Quantis QRNG hardware.

The isolated benchmark does not retain or serialize generated secrets. It writes batches of 1,000 completed operations by default, keeping memory bounded and avoiding a CSV disk write for every very fast AES operation. Set `--keygen-batch 1` for detailed per-operation rows, accepting the extra logging overhead. A native RSA generation already in progress may finish after the deadline; it is censored and excluded from the completed count. Its overrun is recorded. A fixed denominator does not imply that a blocking native cryptographic call can be interrupted at an exact instant.

## Network window and packet definitions

Provisioning and two warm-up sessions occur before timing. A new client/server process pair is used for each network repeat. The client then opens fresh connections sequentially for 60 seconds, with one active handshake at a time. It initiates connection close immediately after the attempt and lets at most 64 close tasks drain in the background. This prevents aioquic close-timer waits from dominating every handshake. Pending-close backpressure and normal event-loop/logging overhead still contribute to the measured workload.

A complete TLS-only session means that the TLS handshake finished and the client validated a nonce-bound ready response. A complete STLS session additionally requires ClientHello, ServerHello, Finished and an authenticated ACK. `tls_handshake_s` records the actual underlying TLS event separately from `total_ready_s`. The baselines authenticate the server; STLS also authenticates the provisioned client. The trust and authentication work differ and must be stated in a comparison.

Packet counters run at both sockets. `client_udp_datagrams_sent` is counted once at the client send call and `server_udp_datagrams_received` once at the server receive callback. One UDP datagram can contain several coalesced QUIC packets, so both counts are exported. QUIC packet counts come from online qlog callbacks without retaining a growing trace. Packet and byte counters use the same monotonic window as the client workload. A single event timestamp is reused for each per-connection/aggregate update to keep totals consistent at the boundary.

UDP byte totals include datagram payloads, including QUIC/TLS bootstrap, padding, ACKs, retransmissions and connection close traffic observed within the window. They exclude IP, UDP and link-layer headers. Each endpoint has its own counters; do not add client-sent and server-received counts to obtain a total number of unique transmissions, because that counts the same traffic twice. Send/receive totals may differ at the boundary because a sent packet can arrive or be processed later. QUIC recovery's `*_declared_lost` is an implementation loss declaration, not a direct physical-link loss measurement.

These packet counts describe the repeated-handshake workload. They are not the maximum packet rate or bandwidth of the link. A higher packet count can indicate extra handshake overhead rather than better performance, so compare completed handshakes and bytes per completed session alongside packet totals. Use the same optional payload for each scenario if you want a handshake-plus-data workload.

The measurement stops counting at its deadline. Pre-deadline errors are `failed`; an unfinished final attempt is `deadline_censored`. Cleanup can continue afterward, but its packets, keys and duration do not extend the denominator. A handshake completed within the window remains completed if its optional later payload fails.

## Raw evidence and stage timings

| File under the corresponding raw folder | Contents |
| --- | --- |
| `raw/.../attempts.csv` | One row per attempt, status, actual negotiated curve, authenticated certificate size, signature algorithm, processing/elapsed times and optional payload result |
| `raw/.../stages.csv` | Three elapsed stages and total for every attempt, including failed/censored rows |
| `raw/.../server_stages.csv` | Server validation, SH construction and Finished verification timing/CPU deltas |
| `raw/.../connection_traffic.csv` | Final per-connection client counters after cleanup, still gated to the window |
| `raw/.../server_totals.json` | Server packet/byte, ephemeral-pair and STLS generation/commit counters |
| `raw/.../resources.csv` | Timestamped client/server RSS and cumulative user+system CPU samples |
| `raw/.../preparation.csv`, `storage.csv` | Excluded-from-window key/certificate preparation and serialized artifact sizes |
| `keygen_raw/.../keygen_batches.csv` | Completed operation counts in bounded batches and failed/censored operation details |
| `keygen_raw/.../keygen_summary.json` | Capacity result with its actual operation definition and timing denominator |

The three elapsed stages are `transport_setup`, `control_exchange` and `validation_confirmation`. They add to `total_session_ready` for successful attempts; the total is not a fourth additive component. STLS local client construction/validation and server validation/response generation are also measured so the manuscript's four processing functions can be reviewed separately. Local processing times exclude network waits and do not add to total latency by themselves.

`request_hash` joins client/server processing records without exposing keys. Server logs retain warm-up rows; match to client attempt hashes when analysing measured attempts. Idempotent retries share a request hash. `connection_traffic.csv` is finalized after draining closes, so it includes in-window close traffic that may occur after that attempt's earlier snapshot.

A `manifest.json` records settings, schedule, dependency versions, machine details and source hashes. Checkpoint JSON is published atomically. No CSV contains raw keys or SIDs. Provisioning JSON and private PEM files are separate secret artifacts and are excluded from the downloadable validation examples.

## Memory and statistical analysis

The parent process samples client and server RSS and user+system CPU time every 100 ms by default. RSS includes Python, cryptographic libraries, warm-up allocations, bounded closing connections and logging buffers; it is not a minimum RAM requirement for embedded firmware. The sampled peak can miss shorter allocation peaks. CPU deltas cover the explicitly recorded sample spans, which are usually slightly shorter than the window. A separate `client_cpu_including_cleanup_s` includes post-window cleanup and should not be presented as exact in-window CPU use. Hardware clock cycles are not fabricated from CPU seconds.

`mean_session_ready_s`, `median_session_ready_s` and nearest-rank `p95_session_ready_s` describe completed attempts; failures/censored attempts remain visible in their count columns. Across-repetition summaries resample whole independent runs rather than treating all handshakes from one run as independent observations. A single run has no SD or bootstrap interval; those cells remain blank. Twenty repeats produce run-level descriptive statistics and 5,000-resample percentile intervals for the mean. They do not remove different trust-model or transport-stack costs.

Use `--device-id laptop_i7_8565U` only when that is the actual executing client machine. Labels do not emulate another processor or commercial IoT device. The optional `project_devices` module remains an explicitly hypothetical frequency model; it is not part of the seven measured defaults and cannot produce real device RAM, battery or radio results.

## Optional acknowledged payload

Handshake-only is the default. Add the same 64 KiB payload to every successful connection:

```powershell
.\.venv\Scripts\python.exe run_experiment.py --payload-bytes 65536
```

Or use a file:

```powershell
.\.venv\Scripts\python.exe run_experiment.py --payload-file "D:\experiment\sample.bin"
```

Payload bytes are loaded once before timing. Framing, hashing and verified receipt are part of the workload. STLS uses directional HKDF keys, strictly increasing data nonces, encrypted metadata and an encrypted receipt. TLS-only scenarios use their authenticated TLS streams. The receiver streams into a digest and discards the data instead of adding file-system writes to the comparison. `payload_s`, `payload_completions` and `payload_bytes` record receipt-verified data. Treat this as a separate workload from handshake-only; it reduces the time available for further handshakes.

## Resume and longer windows

Each finished network or key-capacity window is checkpointed independently. Ctrl+C retains completed results; a later resume skips them and reruns only unfinished windows. Use the same options:

```powershell
.\.venv\Scripts\python.exe run_experiment.py --seconds 60 --runs 1 --resume "results\minute_runs\YOUR_SUITE_DIRECTORY"
```

Settings, direct dependency versions and module source hashes must match. Incomplete raw folders remain available and retry output gets a new folder. The comparison/statistics CSVs are rebuilt from completed checkpoints. Start a new suite after changing source, dependencies, payload or scenarios.

The longer fixed-duration mode remains separate:

```powershell
.\.venv\Scripts\python.exe run_experiment.py --mode factory --factory-seconds 3600 --runs 1
```

It writes under `results/factory_life`. This is a long fixed-time benchmark, not a claim that a physical battery was depleted. Battery degradation and lifetime projections remain outside this experiment.

## Implementation and deployment scope

The original active uploads were TCP prototypes. This package shares their dual-AES/HMAC STLS state machine across QUIC scenarios and retains the earlier TCP entry point only as an optional legacy profile. `client.py`, `server.py` and `run_experiment.py` are entry points; keep the `stls_experiment` folder beside them. `COMPLETE_SOURCE.md` contains every module, test and configuration file without omitted sections.

Length-prefixed `readexactly` framing handles fragmentation and rejects oversized/truncated messages. Credential updates use transcript-bound Finished/ACK and bounded idempotent recovery for lost SH/Finished/ACK messages. Old epochs and invalid sequences are rejected, and a committed epoch can authorize at most one data transfer. HMAC comparisons use `compare_digest`; security checks use explicit exceptions rather than removable assertions. Actual server/client epoch state stays in memory during the run, avoiding shared JSON rewrites and unbounded replay histories on the measured path.

Server restart, persistent anti-rollback recovery, multi-client deployment, protected databases, revocation and secure-element integration need separate deployment work. Every run starts fresh provisioning; it never resets a live session to old provisioning credentials. Python does not guarantee secure erasure. Passing these tests is not a formal security proof, double AES is not a claim of doubled quantum security, and symmetric rolling updates are not TLS ephemeral-DH forward secrecy.

## Verify the code

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

The tests cover all seven real TLS profiles, actual group and certificate-size checks, rejection of a wrong ServerHello group, both packet layers, byte/count reconciliation, actual ephemeral/STLS generation counters, key-capacity batch reconciliation, deadline/aggregate consistency, authenticated payloads, state rotation, lost-message recovery, replay, truncation, tampering, untrusted certificates, silent servers and experiment resumption. `VALIDATION.md` reports the checks actually executed for this delivery. Native Windows execution was not available here; the supplied validation was performed on Linux.

Technical references: [aioquic 1.2.0 source](https://github.com/aiortc/aioquic/tree/1.2.0), [TLS 1.3 RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), and [QUIC TLS RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html).
