# Complete seven scenario experiment source

Version 2. This is the entire runnable source, tests and configuration, without omitted sections. Preserve the displayed relative paths. Read the guide for the distinction between the network and independent key-generation windows.

## run_experiment.py

```python
"""Run all four setups automatically; no separate server terminal is needed."""
from stls_experiment.run_experiment import main

if __name__ == "__main__":
    main()
```

## client.py

```python
"""Entry point: see README.md for the complete automated experiment command."""
from stls_experiment.client import main

if __name__ == "__main__":
    main()
```

## server.py

```python
"""Entry point for the revised TCP or QUIC experiment server."""
from stls_experiment.server import main

if __name__ == "__main__":
    main()
```

## stls_experiment/__init__.py

```python
"""STLS fixed-window experiment suite, version 1.0."""
__version__ = "2.0.0"
```

## stls_experiment/client.py

```python
"""One fixed-window client worker. All elapsed times use a monotonic clock."""
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import logging
import os
import time
from pathlib import Path

import psutil
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.tls import CipherSuite
from .protocol import (ClientState, Credentials, SessionCipher, digest, pack,
                       unpack, require)
from .scenarios import ALL_APPROACHES, scenario
from .transport import ALPN, Channel, Counters, CountingProtocol, OnlineLogger
from .system import metric_pid, write_json
from .tls_profile import configure_tls

ATTEMPT_FIELDS = ["attempt", "request_hash", "status", "error_type", "started_s", "ready_at_s",
    "stage1_transport_s", "stage2_exchange_s", "stage3_confirm_s", "total_ready_s",
    "lifecycle_s", "tls_completed", "tls_resumed", "tls_handshake_s", "app_tx_bytes",
    "app_rx_bytes", "udp_tx_bytes", "udp_rx_bytes", "udp_tx_at_ready", "udp_rx_at_ready",
    "datagrams_tx", "datagrams_rx", "quic_packets_sent", "quic_packets_declared_lost",
    "smoothed_rtt_ms", "client_hello_build_s", "client_hello_cpu_s", "client_validation_s",
    "client_validation_cpu_s", "payload_completed", "payload_bytes", "payload_s",
    "negotiated_group", "signature_algorithm", "peer_certificate_key_bits"]


class CleanupPool:
    """Bound pending closes, without turning 3-PTO waits into handshake latency."""
    def __init__(self, limit=64, writer=None):
        self.limit, self.writer = limit, writer
        self.tasks = set()
        self.max_pending = 0

    async def wait_slot(self):
        if len(self.tasks) >= self.limit:
            await asyncio.wait(self.tasks, return_when=asyncio.FIRST_COMPLETED)

    def schedule(self, context, writer, counts, logger, index):
        async def close():
            try:
                async with asyncio.timeout(2):
                    if context is not None:
                        await context.__aexit__(None, None, None)
                    elif writer is not None:
                        await writer.wait_closed()
            except Exception:
                pass
            if self.writer:
                self.writer.writerow(dict(attempt=index, app_tx_bytes=counts.app_tx,
                    app_rx_bytes=counts.app_rx, udp_tx_bytes=counts.udp_tx,
                    udp_rx_bytes=counts.udp_rx, datagrams_tx=counts.datagrams_tx,
                    datagrams_rx=counts.datagrams_rx,
                    quic_packets_sent=counts.packets_tx,
                    quic_packets_declared_lost=counts.quic_lost,
                    quic_packets_received=counts.packets_rx))
        task = asyncio.create_task(close())
        self.tasks.add(task)
        self.max_pending = max(self.max_pending, len(self.tasks))
        task.add_done_callback(self.tasks.discard)

    async def drain(self):
        await asyncio.gather(*list(self.tasks))


async def attempt(args, state, payload, origin, deadline, index, stats, pool=None, aggregate=None):
    counts = Counters(deadline=deadline, aggregate=aggregate)
    logger = OnlineLogger(counts)
    profile = scenario(args.approach)
    row = {key: "" for key in ATTEMPT_FIELDS}
    row.update(attempt=index, status="error", tls_completed=False, tls_resumed=False,
               payload_completed=False, payload_bytes=0)
    start = time.monotonic()
    row["started_s"] = start - origin
    context, protocol, stream_writer = None, None, None
    stls = args.approach.endswith("stls")
    try:
        # Both per-attempt timeouts and the experiment boundary are enforced.
        async with asyncio.timeout_at(min(deadline, start + args.timeout)):
            if args.approach == "tcp_stls":
                reader, stream_writer = await asyncio.open_connection(args.host, args.port)
            else:
                kind = profile.cert_kind
                configuration = QuicConfiguration(is_client=True, alpn_protocols=ALPN,
                    server_name="localhost", cipher_suites=[CipherSuite.AES_256_GCM_SHA384],
                    quic_logger=logger, idle_timeout=args.timeout, max_datagram_size=args.mtu)
                configuration.load_verify_locations(cafile=str(args.provision / (kind + "-cert.pem")))
                # Fresh config each time, no ticket handler: resumption/0-RTT off.
                context = connect(args.host, args.port, configuration=configuration,
                    create_protocol=lambda *a, **kw: CountingProtocol(*a, counts=counts, **kw))
                protocol = await context.__aenter__()
                # Observe the authenticated peer and the actual selected group;
                # never silently substitute a different curve or RSA modulus.
                tls_context = protocol._quic.tls
                bits = tls_context._peer_certificate.public_key().key_size
                require(tls_context.experiment_group == profile.group, "TLS group mismatch")
                require(bits == (profile.rsa_bits if kind == "rsa" else 256), "certificate key size mismatch")
                row.update(negotiated_group=tls_context.experiment_group,
                           signature_algorithm=tls_context.experiment_signature,
                           peer_certificate_key_bits=bits)
                reader, stream_writer = await protocol.create_stream()
            setup_end = time.monotonic()
            row["stage1_transport_s"] = setup_end - start
            channel = Channel(reader, stream_writer, counts)
            if stls:
                op_start, op_cpu = time.perf_counter(), time.process_time()
                hello = state.client_hello()
                row.update(client_hello_build_s=time.perf_counter()-op_start,
                           client_hello_cpu_s=time.process_time()-op_cpu)
                row["request_hash"] = digest(hello)
                await channel.send(hello)
                response = await channel.receive()
                exchange_end = time.monotonic()
                op_start, op_cpu = time.perf_counter(), time.process_time()
                finished = state.accept_server_hello(response)
                validation_wall = time.perf_counter()-op_start
                validation_cpu = time.process_time()-op_cpu
                await channel.send(finished)
                ack = await channel.receive()
                op_start, op_cpu = time.perf_counter(), time.process_time()
                state.accept_ack(ack)
                row.update(client_validation_s=validation_wall+time.perf_counter()-op_start,
                           client_validation_cpu_s=validation_cpu+time.process_time()-op_cpu)
            else:
                nonce = os.urandom(32).hex()
                hello = pack(dict(kind="READY", nonce=nonce))
                row["request_hash"] = digest(hello)
                await channel.send(hello)
                response = await channel.receive()
                exchange_end = time.monotonic()
                require(unpack(response) == dict(kind="READY_ACK", nonce=nonce), "bad ready reply")
            ready = time.monotonic()
            row.update(stage2_exchange_s=exchange_end - setup_end,
                       stage3_confirm_s=ready - exchange_end,
                       total_ready_s=ready - start, ready_at_s=ready - origin)
            # Completion after the deadline is explicitly right-censored.
            row["status"] = "success" if ready <= deadline else "deadline_censored"
            row["udp_tx_at_ready"] = counts.udp_tx if protocol else ""
            row["udp_rx_at_ready"] = counts.udp_rx if protocol else ""
            if payload:
                transfer_start = time.monotonic()
                tx_cipher = SessionCipher(state.current, "c2s") if stls else None
                rx_cipher = SessionCipher(state.current, "s2c") if stls else None
                metadata = pack(dict(kind="TRANSFER", size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest()))
                await channel.send(tx_cipher.encrypt(metadata) if tx_cipher else metadata)
                for offset in range(0, len(payload), 16384):
                    chunk = payload[offset:offset+16384]
                    await channel.send(tx_cipher.encrypt(chunk) if tx_cipher else chunk)
                receipt = await channel.receive()
                if rx_cipher:
                    receipt = rx_cipher.decrypt(receipt)
                require(unpack(receipt) == dict(kind="TRANSFER_ACK", size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest()), "bad transfer receipt")
                if time.monotonic() <= deadline:
                    row.update(payload_completed=True, payload_bytes=len(payload),
                               payload_s=time.monotonic() - transfer_start)
    except (Exception,) as exc:
        # Preserve a completed handshake if only its later payload failed.
        if row["status"] != "success":
            row["status"] = "deadline_censored" if time.monotonic() >= deadline else "failed"
        row["error_type"] = type(exc).__name__
    finally:
        if stream_writer is not None:
            stream_writer.close()
        if protocol is not None:
            protocol.close()  # Initiate close immediately, then drain asynchronously.
        cleanup = pool if pool is not None else CleanupPool()
        cleanup.schedule(context, stream_writer, counts, logger, index)
        if pool is None:
            await cleanup.drain()  # Warm-up deliberately finishes all cleanup.
    end = time.monotonic()
    row.update(lifecycle_s=end-start, tls_completed=counts.tls_completed,
               tls_resumed=counts.tls_resumed, app_tx_bytes=counts.app_tx,
               app_rx_bytes=counts.app_rx)
    if counts.tls_completed:
        row["tls_handshake_s"] = counts.tls_complete_at - start
        if counts.tls_complete_at <= deadline:
            stats["tls_handshakes"] += 1
    if args.approach != "tcp_stls":
        row.update(udp_tx_bytes=counts.udp_tx, udp_rx_bytes=counts.udp_rx,
                   datagrams_tx=counts.datagrams_tx, datagrams_rx=counts.datagrams_rx)
        if logger.trace:
            row.update(quic_packets_sent=counts.packets_tx,
                quic_packets_declared_lost=counts.quic_lost,
                smoothed_rtt_ms=logger.trace.smoothed_rtt_ms)
    return row


async def worker(args):
    args.out.mkdir(parents=True, exist_ok=True)
    aggregate = Counters(deadline=0)
    configure_tls(scenario(args.approach), aggregate)
    state = ClientState(Credentials.from_dict(json.loads((args.provision / "client.json").read_text())))
    # Allocate once, before warm-up or timing, identically across approaches.
    payload = args.payload_file.read_bytes() if args.payload_file else b"X" * args.payload_bytes
    stats = dict(tls_handshakes=0)
    for index in range(args.warmup):
        result = await attempt(args, state, payload, time.monotonic(), float("inf"), index, stats)
        if result["status"] != "success":
            raise RuntimeError("warm-up failed: " + result["error_type"])
    stats = dict(tls_handshakes=0)
    # Sampling stays in the parent process, so it does not compete for this GIL.
    process = psutil.Process(metric_pid())
    write_json(args.out / "worker_ready.json", dict(
        pid=os.getpid(), metric_pid=metric_pid(), baseline_rss_bytes=process.memory_info().rss))
    if args.go:
        while not args.go.exists():
            await asyncio.sleep(0.01)
    origin = time.monotonic()
    deadline = origin + args.seconds
    cpu_start = time.process_time()
    completed = failed = censored = 0
    totals = dict(payload_bytes=0, payload_completions=0)
    aggregate.start, aggregate.deadline = origin, deadline
    write_json(args.out / "window.json", dict(start_monotonic=origin,
        deadline_monotonic=deadline, duration_s=args.seconds))
    with (args.out / "attempts.csv").open("w", newline="", encoding="utf-8") as af, \
         (args.out / "stages.csv").open("w", newline="", encoding="utf-8") as sf, \
         (args.out / "connection_traffic.csv").open("w", newline="", encoding="utf-8") as tf:
        attempts = csv.DictWriter(af, fieldnames=ATTEMPT_FIELDS)
        stages = csv.DictWriter(sf, fieldnames=["attempt", "request_hash", "stage", "duration_s", "status"])
        attempts.writeheader()
        stages.writeheader()
        traffic = csv.DictWriter(tf, fieldnames=["attempt", "app_tx_bytes", "app_rx_bytes",
            "udp_tx_bytes", "udp_rx_bytes", "datagrams_tx", "datagrams_rx", "quic_packets_sent",
            "quic_packets_declared_lost", "quic_packets_received"])
        traffic.writeheader()
        pool = CleanupPool(args.max_pending_closes, traffic)
        index = 0
        while time.monotonic() < deadline:
            await pool.wait_slot()
            if time.monotonic() >= deadline:
                break
            index += 1
            row = await attempt(args, state, payload, origin, deadline, index, stats, pool, aggregate)
            attempts.writerow(row)
            for label, key in (("transport_setup", "stage1_transport_s"),
                               ("control_exchange", "stage2_exchange_s"),
                               ("validation_confirmation", "stage3_confirm_s"),
                               ("total_session_ready", "total_ready_s")):
                stages.writerow(dict(attempt=index, request_hash=row["request_hash"],
                    stage=label, duration_s=row[key], status=row["status"]))
            completed += row["status"] == "success"
            failed += row["status"] == "failed"
            censored += row["status"] == "deadline_censored"
            totals["payload_bytes"] += row["payload_bytes"]
            totals["payload_completions"] += row["payload_completed"]
        await pool.drain()
    totals.update(app_tx_bytes=aggregate.app_tx, app_rx_bytes=aggregate.app_rx,
                  udp_tx_bytes=aggregate.udp_tx, udp_rx_bytes=aggregate.udp_rx,
                  client_udp_datagrams_sent=aggregate.datagrams_tx,
                  client_udp_datagrams_received=aggregate.datagrams_rx,
                  client_quic_packets_sent=aggregate.packets_tx,
                  client_quic_packets_received=aggregate.packets_rx,
                  client_quic_packets_declared_lost=aggregate.quic_lost,
                  client_ephemeral_key_pairs_generated=aggregate.ephemeral_key_pairs)
    summary = dict(duration_s=args.seconds, measurement_kind="physical_host_measurement",
        attempts=index, completed_handshakes=completed, failed_attempts=failed,
        deadline_censored=censored, handshakes_per_minute=completed * 60 / args.seconds,
        client_cpu_including_cleanup_s=time.process_time()-cpu_start,
        cleanup_overrun_s=max(0, time.monotonic()-deadline),
        max_pending_closes_observed=pool.max_pending,
        **stats, **totals)
    summary["application_bytes_per_s"] = (totals["app_tx_bytes"]+totals["app_rx_bytes"])/args.seconds
    summary["udp_payload_bytes_per_s"] = ((totals["udp_tx_bytes"]+totals["udp_rx_bytes"])/args.seconds
                                            if args.approach != "tcp_stls" else None)
    if args.approach == "tcp_stls":
        summary["udp_tx_bytes"] = summary["udp_rx_bytes"] = None
    write_json(args.out / "worker_summary.json", summary)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approach", choices=ALL_APPROACHES, required=True)
    p.add_argument("--provision", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--seconds", type=float, default=60)
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--warmup", type=int, default=2)
    p.add_argument("--mtu", type=int, default=1200)
    p.add_argument("--go", type=Path)
    p.add_argument("--max-pending-closes", type=int, default=64)
    payload = p.add_mutually_exclusive_group()
    payload.add_argument("--payload-bytes", type=int, default=0)
    payload.add_argument("--payload-file", type=Path)
    a = p.parse_args()
    if a.seconds <= 0 or a.timeout <= 0 or a.warmup < 0 or a.max_pending_closes < 1 or not 0 <= a.payload_bytes <= 1073741824:
        p.error("invalid duration, timeout, warm-up or payload size")
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(worker(a))


if __name__ == "__main__":
    main()
```

## stls_experiment/key_generation.py

```python
"""Independent fixed-window key-generation capacity, without certificate issuance.

RSA/EC operations create one private/public pair. STLS creates one bundle of
two independent AES-256 keys plus a 32-byte SID, exactly as Credentials.generate
does in the network protocol. Individual symmetric keys and pairs are reported
in separate columns; a bundle is not mislabeled as one RSA-equivalent key.
"""
import argparse
import csv
import math
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from .protocol import Credentials
from .scenarios import ALL_APPROACHES, scenario
from .system import write_json

CURVES = dict(secp256r1=ec.SECP256R1, secp384r1=ec.SECP384R1, secp521r1=ec.SECP521R1)


def generate_material(profile):
    if profile.stls:
        return Credentials.generate("keygen")
    if profile.cert_kind == "rsa":
        private = rsa.generate_private_key(public_exponent=65537, key_size=profile.rsa_bits)
    else:
        private = ec.generate_private_key(CURVES[profile.group]())
    return private, private.public_key()


def run(args):
    args.out.mkdir(parents=True, exist_ok=True)
    profile = scenario(args.approach)
    for _ in range(args.warmup):
        generate_material(profile)
    with (args.out / "keygen_batches.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["batch", "started_s", "ended_s", "completed_operations",
            "cpu_s", "last_operation_wall_s", "status", "error_type"])
        writer.writeheader()
        start = time.monotonic()
        deadline = start + args.seconds
        cpu = time.process_time()
        completed = failed = censored = attempts = batch = pending = 0
        batch_start, batch_cpu = start, cpu
        write_json(args.out / "keygen_window.json", dict(start_monotonic=start,
            deadline_monotonic=deadline, duration_s=args.seconds))
        while time.monotonic() < deadline:
            attempts += 1
            op_start = time.monotonic()
            error, status = "", "completed"
            try:
                material = generate_material(profile)
                ended = time.monotonic()
                if ended <= deadline:
                    completed += 1
                    pending += 1
                else:
                    censored += 1
                    status = "deadline_censored"
                del material  # Do not retain millions of keys or serialize secrets.
            except Exception as exc:
                ended = time.monotonic()
                error = type(exc).__name__
                if ended >= deadline:
                    censored += 1
                    status = "deadline_censored"
                else:
                    failed += 1
                    status = "failed"
            if pending >= args.batch_size or status != "completed" or ended >= deadline:
                batch += 1
                writer.writerow(dict(batch=batch, started_s=batch_start-start, ended_s=ended-start,
                    completed_operations=pending, cpu_s=time.process_time()-batch_cpu,
                    last_operation_wall_s=ended-op_start, status=status, error_type=error))
                pending = 0
                batch_start, batch_cpu = time.monotonic(), time.process_time()
        if pending:
            batch += 1
            writer.writerow(dict(batch=batch, started_s=batch_start-start, ended_s=time.monotonic()-start,
                completed_operations=pending, cpu_s=time.process_time()-batch_cpu,
                last_operation_wall_s="", status="completed", error_type=""))
        result = dict(approach=args.approach, duration_s=args.seconds,
            operation="two_AES256_keys_plus_SID" if profile.stls else (
                f"RSA{profile.rsa_bits}_key_pair" if profile.cert_kind=="rsa" else f"ECDHE_{profile.group}_key_pair"),
            attempts=attempts, completed_key_generation_operations=completed,
            failed_operations=failed, deadline_censored_operations=censored,
            generated_key_pairs=0 if profile.stls else completed,
            generated_symmetric_keys=2*completed if profile.stls else 0,
            generated_sids=completed if profile.stls else 0,
            key_generation_operations_per_minute=completed*60/args.seconds,
            key_pairs_per_minute=0 if profile.stls else completed*60/args.seconds,
            symmetric_keys_per_minute=2*completed*60/args.seconds if profile.stls else 0,
            cpu_including_overrun_s=time.process_time()-cpu,
            final_operation_overrun_s=max(0,time.monotonic()-deadline), batch_size=args.batch_size)
    write_json(args.out / "keygen_summary.json", result)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approach", choices=ALL_APPROACHES, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seconds", type=float, default=60)
    p.add_argument("--warmup", type=int, default=1)
    p.add_argument("--batch-size", type=int, default=1000)
    a = p.parse_args()
    if not math.isfinite(a.seconds) or a.seconds<=0 or a.warmup<0 or a.batch_size<1:
        p.error("duration must be positive and finite; warm-up nonnegative; batch size positive")
    run(a)


if __name__ == "__main__":
    main()
```

## stls_experiment/project_devices.py

```python
"""Optional, explicitly hypothetical frequency projections; never hardware results.

The provided assumptions reproduce manuscript Table 6, not verified product
specifications. CPU frequency alone cannot predict a different ISA, compiler,
radio, cryptographic acceleration, RAM use or embedded protocol implementation.
Do not use these rows as evidence that the commercial devices ran this code.
"""
import argparse
import csv
import json
import math
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("runs", type=Path)
    p.add_argument("--profiles", type=Path, default=Path("device_assumptions.json"))
    p.add_argument("--reference-mhz", type=float, required=True,
                   help="explicit baseline frequency assumption, not automatically detected")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    if not math.isfinite(a.reference_mhz) or a.reference_mhz <= 0:
        p.error("reference MHz must be finite and positive")
    profiles = json.loads(a.profiles.read_text())["profiles"]
    a.out.mkdir(parents=True, exist_ok=False)
    with a.runs.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    fields = ["device_id", "source_device", "approach", "repeat", "measurement_kind", "method",
        "reference_mhz_assumption", "device_mhz_assumption", "duration_s", "modeled_expected_handshakes",
        "modeled_handshakes_per_minute", "modeled_application_bytes", "modeled_udp_payload_bytes"]
    with (a.out / "modeled_runs.csv").open("w", newline="", encoding="utf-8") as allf:
        allw = csv.DictWriter(allf, fieldnames=fields)
        allw.writeheader()
        for profile in profiles:
            frequency = float(profile["mhz_assumption"])
            if not math.isfinite(frequency) or frequency <= 0:
                raise ValueError("device frequency must be finite and positive")
            ratio = frequency / a.reference_mhz
            with (a.out / (profile["device_id"] + "_handshakes_MODELED.csv")).open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                for r in rows:
                    result = dict(device_id=profile["device_id"], source_device=r["device_id"],
                        approach=r["approach"], repeat=r["repeat"], measurement_kind="hypothetical_frequency_projection",
                        method="all_wall_time_and_rate_scaled_by_clock_ratio_only",
                        reference_mhz_assumption=a.reference_mhz, device_mhz_assumption=frequency,
                        duration_s=r["duration_s"],
                        modeled_expected_handshakes=float(r["completed_handshakes"])*ratio,
                        modeled_handshakes_per_minute=float(r["handshakes_per_minute"])*ratio,
                        modeled_application_bytes=(float(r["app_tx_bytes"])+float(r["app_rx_bytes"]))*ratio,
                        modeled_udp_payload_bytes=(float(r["udp_tx_bytes"])+float(r["udp_rx_bytes"]))*ratio
                            if r["udp_tx_bytes"] else "")
                    w.writerow(result)
                    allw.writerow(result)
    (a.out / "assumptions.json").write_text(json.dumps(dict(source=str(a.runs.resolve()),
        reference_mhz=a.reference_mhz, profiles=profiles,
        caution="Hypothetical model only. RAM, flash, battery and radio performance are not measured or inferred."), indent=2))
    print(f"Wrote explicitly MODELED results to {a.out}")


if __name__ == "__main__":
    main()
```

## stls_experiment/protocol.py

```python
"""Transport-independent STLS research protocol.

Retains the uploaded prototype's nested AES-256-GCM and HMAC-SHA256 design.
Adds explicit version/direction binding, epochs, transcript binding, bounded
state and an authenticated Finished/ACK. This is a new, documented wire format,
not a claim to implement a standardized replacement for QUIC TLS.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
MAX_FRAME = 65536


class ProtocolError(ValueError):
    """Authentication, framing or state validation failed."""


def pack(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def unpack(data: bytes) -> dict:
    if len(data) > MAX_FRAME:
        raise ProtocolError("oversized message")
    try:
        result = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if not isinstance(result, dict):
        raise ProtocolError("message must be an object")
    return result


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ProtocolError("invalid base64") from exc


def require(condition: bool, reason: str) -> None:
    # Never use assert for security checks: python -O removes assertions.
    if not condition:
        raise ProtocolError(reason)


@dataclass(frozen=True)
class Credentials:
    cid: str
    key1: bytes
    key2: bytes
    sid: bytes
    epoch: int = 0

    @classmethod
    def generate(cls, cid: str, epoch: int = 0) -> Credentials:
        require(isinstance(cid, str) and 1 <= len(cid) <= 64, "invalid CID")
        return cls(cid, os.urandom(32), os.urandom(32), os.urandom(32), epoch)

    def to_dict(self) -> dict:
        # Used ONLY for secure provisioning/state, never a performance CSV.
        return dict(cid=self.cid, key1=b64(self.key1), key2=b64(self.key2),
                    sid=b64(self.sid), epoch=self.epoch)

    @classmethod
    def from_dict(cls, value: dict) -> Credentials:
        try:
            c = cls(value["cid"], unb64(value["key1"]), unb64(value["key2"]),
                    unb64(value["sid"]), value["epoch"])
            require(all(len(k) == 32 for k in (c.key1, c.key2, c.sid)), "bad key length")
            require(type(c.epoch) is int and c.epoch >= 0, "bad epoch")
            require(isinstance(c.cid, str) and 1 <= len(c.cid) <= 64, "bad CID")
            return c
        except (KeyError, TypeError) as exc:
            raise ProtocolError("bad credentials") from exc


def subkey(creds: Credentials, purpose: str) -> bytes:
    # Independent direction/purpose keys also separate the two AEAD layers.
    source = creds.key1 if purpose.endswith("outer") else creds.key2
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=creds.sid,
                info=("STLS-v1/" + purpose).encode()).derive(source)


def encrypt_layer(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_layer(key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    require(len(ciphertext) >= 28, "short AEAD record")
    return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], aad)


def seal(creds: Credentials, kind: str, body: dict) -> bytes:
    header = dict(v=VERSION, cid=creds.cid, epoch=creds.epoch, kind=kind)
    aad = pack(header)
    raw = pack(body)
    inner = encrypt_layer(subkey(creds, kind + "/inner"), raw, aad)
    mac = hmac.digest(creds.sid, aad + inner, "sha256")
    protected = pack(dict(inner=b64(inner), mac=b64(mac)))
    header["encrypted"] = b64(encrypt_layer(subkey(creds, kind + "/outer"), protected, aad))
    return pack(header)


def open_message(creds: Credentials, kind: str, data: bytes) -> dict:
    envelope = unpack(data)
    header = {k: envelope.get(k) for k in ("v", "cid", "epoch", "kind")}
    require(header == dict(v=VERSION, cid=creds.cid, epoch=creds.epoch, kind=kind),
            "version, identity, direction or epoch mismatch")
    aad = pack(header)
    try:
        outer = unpack(decrypt_layer(subkey(creds, kind + "/outer"),
                                     unb64(envelope["encrypted"]), aad))
        inner = unb64(outer["inner"])
        require(hmac.compare_digest(unb64(outer["mac"]),
                                   hmac.digest(creds.sid, aad + inner, "sha256")), "HMAC mismatch")
        return unpack(decrypt_layer(subkey(creds, kind + "/inner"), inner, aad))
    except (KeyError, TypeError) as exc:
        raise ProtocolError("missing protected field") from exc


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ClientState:
    def __init__(self, creds: Credentials):
        self.current = creds
        self.request: bytes | None = None
        self.request_nonce = ""
        self.candidate: Credentials | None = None
        self.transcript = ""

    def client_hello(self) -> bytes:
        # An interrupted exchange retries identical CH; never silently reprovision.
        if self.request is None:
            self.request_nonce = b64(os.urandom(32))
            self.request = seal(self.current, "CH", dict(sid=b64(self.current.sid),
                nonce=self.request_nonce, session=self.current.epoch, sequence=0))
        return self.request

    def accept_server_hello(self, data: bytes) -> bytes:
        require(self.request is not None, "unsolicited ServerHello")
        body = open_message(self.current, "SH", data)
        require(body.get("request_hash") == digest(self.request), "wrong request transcript")
        require(body.get("nonce") == self.request_nonce, "wrong nonce")
        require(body.get("old_sid") == b64(self.current.sid), "wrong old SID")
        new = Credentials.from_dict(body["next"])
        require(new.cid == self.current.cid and new.epoch == self.current.epoch + 1,
                "invalid credential transition")
        self.candidate = new
        self.transcript = digest(self.request + data)
        return seal(new, "FIN", dict(transcript=self.transcript, sequence=1))

    def accept_ack(self, data: bytes) -> None:
        require(self.candidate is not None, "unsolicited ACK")
        body = open_message(self.candidate, "ACK", data)
        require(body == dict(transcript=self.transcript, sequence=2), "bad ACK transcript")
        self.current = self.candidate
        self.candidate = None
        self.request = None


class ServerState:
    """One serial client per experiment; bounded current/previous transaction.

    Cached ciphertext replies are idempotent retransmissions, not fresh accepted
    handshakes. A new valid epoch discards the previous transaction. In-memory
    state is intentional for runtime benchmarking; restart requires a new securely
    provisioned experiment, not reuse of the initial state for a deployed fleet.
    """
    def __init__(self, creds: Credentials):
        self.current = creds
        self.pending: Credentials | None = None
        self.request: bytes | None = None
        self.response: bytes | None = None
        self.transcript = ""
        self.ack: bytes | None = None
        self.last_finished: bytes | None = None
        self.transfer_started = False

    def validate_hello(self, data: bytes) -> dict:
        # This cached reply can recover a lost SH/ACK without rotating twice.
        if self.request == data:
            return {"retry": True}
        body = open_message(self.current, "CH", data)
        require(body.get("sid") == b64(self.current.sid), "SID mismatch")
        require(body.get("session") == self.current.epoch and body.get("sequence") == 0,
                "stale session or sequence")
        require(len(unb64(body.get("nonce"))) == 32, "invalid freshness nonce")
        require(self.pending is None, "unconfirmed exchange requires identical retry")
        return body

    def make_server_hello(self, data: bytes, body: dict) -> bytes:
        if body.get("retry"):
            require(self.response is not None, "missing cached response")
            return self.response
        self.pending = Credentials.generate(self.current.cid, self.current.epoch + 1)
        self.request = data
        self.response = seal(self.current, "SH", dict(old_sid=b64(self.current.sid),
            nonce=body["nonce"], request_hash=digest(data), next=self.pending.to_dict()))
        self.transcript = digest(data + self.response)
        self.ack = None
        self.last_finished = None
        self.transfer_started = False
        return self.response

    def authorize_transfer(self, creds: Credentials) -> None:
        require(creds == self.current and self.pending is None, "stale transfer session")
        require(not self.transfer_started, "transfer already consumed for this epoch")
        self.transfer_started = True

    def finish(self, data: bytes) -> bytes:
        if data == self.last_finished and self.ack is not None:
            return self.ack
        if self.pending is None and self.ack is not None:
            body = open_message(self.current, "FIN", data)
            require(body == dict(transcript=self.transcript, sequence=1), "bad retry Finished")
            return self.ack
        require(self.pending is not None, "unexpected Finished")
        body = open_message(self.pending, "FIN", data)
        require(body == dict(transcript=self.transcript, sequence=1), "bad Finished transcript")
        self.ack = seal(self.pending, "ACK", dict(transcript=self.transcript, sequence=2))
        self.current = self.pending
        self.pending = None
        self.last_finished = data
        return self.ack


class SessionCipher:
    """Directional sequence nonces for optional data transfer under fresh keys."""
    def __init__(self, creds: Credentials, direction: str):
        self.key = subkey(creds, "DATA/" + direction + "/inner")
        self.sequence = 0
        self.aad = pack(dict(v=VERSION, cid=creds.cid, epoch=creds.epoch, direction=direction))

    def encrypt(self, data: bytes) -> bytes:
        require(self.sequence < 2**64, "sequence exhausted")
        nonce = b"\x00" * 4 + self.sequence.to_bytes(8, "big")
        self.sequence += 1
        return nonce + AESGCM(self.key).encrypt(nonce, data, self.aad)

    def decrypt(self, data: bytes) -> bytes:
        require(len(data) >= 28, "short data record")
        nonce = b"\x00" * 4 + self.sequence.to_bytes(8, "big")
        require(data[:12] == nonce, "replayed or out-of-order data")
        result = AESGCM(self.key).decrypt(nonce, data[12:], self.aad)
        self.sequence += 1
        return result
```

## stls_experiment/provision.py

```python
"""Create independent client/server provisioning and pinned local test certs."""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from .protocol import Credentials
from .scenarios import scenario, ALL_APPROACHES


def private_write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def provision(folder: Path, cid="client123", rsa_bits=2048, approach=None) -> list[dict]:
    folder.mkdir(parents=True, exist_ok=True)
    if any(folder.iterdir()):
        raise FileExistsError("provisioning folder must be empty; never overwrite credentials")
    creds = Credentials.generate(cid).to_dict()
    private_write(folder / "client.json", json.dumps(creds).encode())
    private_write(folder / "server.json", json.dumps(creds).encode())
    rows = []
    profile = scenario(approach) if approach else None
    if profile and profile.cert_kind == "rsa":
        rsa_bits = profile.rsa_bits
    kinds = (profile.cert_kind,) if profile and profile.cert_kind != "none" else (() if profile else ("rsa", "ecdsa"))
    for kind in kinds:
        start, cpu = time.perf_counter(), time.process_time()
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits) if kind == "rsa" else ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1"))]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        private_write(folder / (kind + "-key.pem"), key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        (folder / (kind + "-cert.pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        rows.append(dict(algorithm=kind, wall_s=time.perf_counter()-start,
            cpu_s=time.process_time()-cpu, certificate_der_bytes=len(cert.public_bytes(serialization.Encoding.DER)),
            private_key_der_bytes=len(key.private_bytes(serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))))
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--cid", default="client123")
    p.add_argument("--rsa-bits", type=int, choices=[2048, 3072, 4096], default=2048)
    p.add_argument("--approach", choices=ALL_APPROACHES)
    a = p.parse_args()
    print(json.dumps(provision(a.out, a.cid, a.rsa_bits, a.approach), indent=2))


if __name__ == "__main__":
    main()
```

## stls_experiment/run_experiment.py

```python
"""Seven QUIC scenarios: independent timed networking and key-generation windows."""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

import psutil
from .provision import provision
from .scenarios import APPROACHES, ALL_APPROACHES, scenario
from .system import write_json


def append_csv(path: Path, row: dict) -> None:
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if not exists:
            w.writeheader()
        w.writerow(row)


def wait_file(path: Path, process: subprocess.Popen, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            json.loads(path.read_text())
            return
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        if process.poll() is not None:
            raise RuntimeError(f"process exited {process.returncode}; inspect {path.parent} logs")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"waiting for {path.name}; inspect {path.parent} logs")
        time.sleep(0.02)


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def resource_sample(client, server):
    row = dict(monotonic_s=time.monotonic())
    for side, process in (("client", client), ("server", server)):
        try:
            with process.oneshot():
                row[side + "_rss_bytes"] = process.memory_info().rss
                cpu = process.cpu_times()
                row[side + "_cpu_s"] = cpu.user + cpu.system
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            row[side + "_rss_bytes"] = row[side + "_cpu_s"] = ""
    return row


def resource_summary(rows, window):
    selected = [r for r in rows if window["start_monotonic"] <= r["monotonic_s"] <= window["deadline_monotonic"]]
    result = dict(resource_samples=len(selected))
    for side in ("client", "server"):
        rss = [r[side + "_rss_bytes"] for r in selected if r[side + "_rss_bytes"] != ""]
        cpu = [r for r in selected if r[side + "_cpu_s"] != ""]
        result[side + "_sampled_peak_rss_bytes"] = max(rss) if rss else None
        result[side + "_sampled_mean_rss_bytes"] = statistics.fmean(rss) if rss else None
        result[side + "_sampled_cpu_s"] = cpu[-1][side + "_cpu_s"]-cpu[0][side + "_cpu_s"] if len(cpu)>1 else None
        span = cpu[-1]["monotonic_s"]-cpu[0]["monotonic_s"] if len(cpu)>1 else 0
        result[side + "_cpu_sample_span_s"] = span
        result[side + "_sampled_cpu_percent_one_core"] = result[side + "_sampled_cpu_s"]*100/span if span else None
    return result


def run_one(root, job, args, ordinal):
    profile = scenario(job["approach"])
    name = f"{ordinal:04d}_{job['approach']}_r{job['repeat']:02d}"
    folder = root / "raw" / name
    # A retry after interruption uses a new folder; retain the incomplete evidence.
    suffix = 0
    while folder.exists():
        suffix += 1
        folder = root / "raw" / (name + f"_retry{suffix}")
    folder.mkdir(parents=True)
    preparation = provision(folder / "provision", approach=job["approach"])
    for row in preparation:
        append_csv(folder / "preparation.csv", row)
    for path in sorted((folder / "provision").iterdir()):
        append_csv(folder / "storage.csv", dict(artifact=path.name, size_bytes=path.stat().st_size,
            meaning="host serialized provisioning artifact; not embedded flash footprint"))
    ready = folder / "server_ready.json"
    go = folder / "go"
    server_command = [sys.executable, "-m", "stls_experiment.server", "--approach", job["approach"],
        "--provision", str(folder / "provision"), "--ready", str(ready), "--log", str(folder / "server_stages.csv"),
        "--mtu", str(args.mtu), "--timeout", str(args.timeout), "--window", str(folder/"window.json")]
    server = client = None
    samples = []
    with (folder / "server.log").open("w") as slog, (folder / "client.log").open("w") as clog:
        try:
            server = subprocess.Popen(server_command, stdout=slog, stderr=subprocess.STDOUT)
            wait_file(ready, server, 30)
            port = json.loads(ready.read_text())["port"]
            command = [sys.executable, "-m", "stls_experiment.client", "--approach", job["approach"],
                "--provision", str(folder / "provision"), "--port", str(port), "--out", str(folder),
                "--seconds", str(args.duration), "--timeout", str(args.timeout), "--warmup", str(args.warmup),
                "--mtu", str(args.mtu), "--max-pending-closes", str(args.max_pending_closes), "--go", str(go)]
            if args.payload_file:
                command += ["--payload-file", str(args.payload_file)]
            else:
                command += ["--payload-bytes", str(args.payload_bytes)]
            client = subprocess.Popen(command, stdout=clog, stderr=subprocess.STDOUT)
            wait_file(folder / "worker_ready.json", client, 60 + args.timeout * max(1,args.warmup))
            client_pid = json.loads((folder / "worker_ready.json").read_text())["metric_pid"]
            server_pid = json.loads(ready.read_text())["metric_pid"]
            cp, sp = psutil.Process(client_pid), psutil.Process(server_pid)
            samples.append(resource_sample(cp, sp))
            go.touch()
            guard = time.monotonic() + args.duration + args.timeout + 15
            while client.poll() is None:
                samples.append(resource_sample(cp, sp))
                if server.poll() is not None:
                    raise RuntimeError("server exited during measurement")
                if time.monotonic() > guard:
                    raise TimeoutError("worker exceeded measurement and cleanup allowance")
                time.sleep(args.sample_interval)
            if client.returncode:
                raise RuntimeError("client failed; inspect " + str(folder / "client.log"))
            wait_file(folder / "worker_summary.json", client, 1)
            # Gracefully drain server CSVs on both Windows and Unix.
            ready.with_suffix(".stop").touch()
            server.wait(timeout=5)
            if server.returncode:
                raise RuntimeError("server did not shut down cleanly")
        finally:
            if client:
                stop_process(client)
            if server:
                stop_process(server)
    window = json.loads((folder / "window.json").read_text())
    with (folder / "resources.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["elapsed_s", *samples[0]])
        w.writeheader()
        for row in samples:
            w.writerow(dict(elapsed_s=row["monotonic_s"]-window["start_monotonic"], **row))
    summary = json.loads((folder / "worker_summary.json").read_text())
    server_totals = json.loads((folder / "server_totals.json").read_text())
    result = dict(device_id=args.device_id, approach=job["approach"], repeat=job["repeat"],
                  order=ordinal, raw_folder=folder.relative_to(root).as_posix(), **summary,
                  **server_totals, **resource_summary(samples, window))
    result["client_baseline_rss_bytes"] = json.loads((folder / "worker_ready.json").read_text())["baseline_rss_bytes"]
    result["payload_size_bytes"] = args.payload_file.stat().st_size if args.payload_file else args.payload_bytes
    result["connection_policy"] = "fresh_serial_handshakes_bounded_overlapping_teardown"
    result["certificate_algorithm"] = f"RSA{profile.rsa_bits}" if profile.cert_kind=="rsa" else ("ECDSA_P256" if profile.cert_kind=="ecdsa" else "none")
    result["tls_cipher"] = "" if job["approach"] == "tcp_stls" else "AES_256_GCM_SHA384"
    result["tls_group"] = profile.group
    result["long_term_certificate_key_pairs_generated_in_window"] = 0
    result["client_stls_symmetric_keys_installed"] = 2*result["completed_handshakes"] if profile.stls else 0
    # Descriptive latency of completed sessions. Censored work remains in the
    # count/failure columns rather than becoming a false short latency sample.
    with (folder/"attempts.csv").open(newline="",encoding="utf-8") as f:
        latencies=[float(r["total_ready_s"]) for r in csv.DictReader(f) if r["status"]=="success"]
    result["mean_session_ready_s"] = statistics.fmean(latencies) if latencies else None
    result["median_session_ready_s"] = statistics.median(latencies) if latencies else None
    result["p95_session_ready_s"] = sorted(latencies)[math.ceil(.95*len(latencies))-1] if latencies else None
    result["client_udp_datagrams_per_minute"] = result["client_udp_datagrams_sent"]*60/args.duration
    result["server_udp_datagrams_per_minute"] = result["server_udp_datagrams_sent"]*60/args.duration
    write_json(folder / "run_summary.json", result)
    return result


def run_keys(root, job, args, ordinal):
    folder = root / "keygen_raw" / f"{ordinal:04d}_{job['approach']}_r{job['repeat']:02d}"
    suffix = 0
    while folder.exists():
        suffix += 1
        folder = root / "keygen_raw" / f"{ordinal:04d}_{job['approach']}_r{job['repeat']:02d}_retry{suffix}"
    folder.mkdir(parents=True)
    with (folder / "keygen.log").open("w") as log:
        process = subprocess.Popen([sys.executable, "-m", "stls_experiment.key_generation",
            "--approach", job["approach"], "--out", str(folder), "--seconds", str(args.duration),
            "--warmup", str(args.keygen_warmup), "--batch-size", str(args.keygen_batch)],
            stdout=log, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=args.duration+180)
            if process.returncode:
                raise RuntimeError("key generation failed; inspect " + str(folder/"keygen.log"))
        finally:
            stop_process(process)
    result = json.loads((folder/"keygen_summary.json").read_text())
    return dict(device_id=args.device_id, repeat=job["repeat"],
                keygen_raw_folder=folder.relative_to(root).as_posix(), **result)


def export_comparison(root):
    """Join the separate capacity and network windows by scenario/repeat."""
    keys = {}
    if (root/"key_generation.csv").exists():
        with (root/"key_generation.csv").open(newline="", encoding="utf-8") as f:
            keys = {(r["approach"],r["repeat"]):r for r in csv.DictReader(f)}
    rows = []
    if (root/"runs.csv").exists():
        with (root/"runs.csv").open(newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                k = keys.get((r["approach"],r["repeat"]),{})
                rows.append(dict(device_id=r["device_id"], approach=r["approach"], repeat=r["repeat"],
                    network_window_s=r["duration_s"], keygen_window_s=k.get("duration_s",""),
                    certificate_algorithm=r["certificate_algorithm"], tls_group=r["tls_group"],
                    completed_handshakes=r["completed_handshakes"], handshakes_per_minute=r["handshakes_per_minute"],
                    mean_session_ready_s=r["mean_session_ready_s"],
                    client_udp_datagrams_sent=r["client_udp_datagrams_sent"],
                    client_udp_datagrams_received=r["client_udp_datagrams_received"],
                    server_udp_datagrams_sent=r["server_udp_datagrams_sent"],
                    server_udp_datagrams_received=r["server_udp_datagrams_received"],
                    client_quic_packets_sent=r["client_quic_packets_sent"],
                    client_quic_packets_received=r["client_quic_packets_received"],
                    server_quic_packets_sent=r["server_quic_packets_sent"],
                    server_quic_packets_received=r["server_quic_packets_received"],
                    client_ephemeral_key_pairs_generated=r["client_ephemeral_key_pairs_generated"],
                    server_ephemeral_key_pairs_generated=r["server_ephemeral_key_pairs_generated"],
                    server_stls_symmetric_keys_generated=r["server_stls_symmetric_keys_generated"],
                    long_term_certificate_key_pairs_generated_in_network_window=r["long_term_certificate_key_pairs_generated_in_window"],
                    key_generation_operations=k.get("completed_key_generation_operations",""),
                    generated_key_pairs=k.get("generated_key_pairs",""),
                    generated_symmetric_keys=k.get("generated_symmetric_keys",""),
                    key_generation_operations_per_minute=k.get("key_generation_operations_per_minute",""),
                    failed_handshakes=r["failed_attempts"], deadline_censored_handshakes=r["deadline_censored"]))
    if rows:
        with (root/"comparison.csv").open("w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def export_device_files(root, device):
    """Rebuild derived files from the run checkpoint without duplicating rows."""
    with (root / "runs.csv").open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for target in (root / f"{device}_handshakes.csv", root / f"{device}_stages.csv"):
        if target.exists():
            target.unlink()
    with (root / f"{device}_handshakes.csv").open("w", newline="", encoding="utf-8") as hf, \
         (root / f"{device}_stages.csv").open("w", newline="", encoding="utf-8") as sf:
        hw = csv.DictWriter(hf, fieldnames=list(rows[0]))
        hw.writeheader()
        sw = csv.DictWriter(sf, fieldnames=["device_id", "approach", "repeat", "attempt", "request_hash", "stage", "duration_s", "status"])
        sw.writeheader()
        for row in rows:
            hw.writerow(row)
            with (root / row["raw_folder"] / "stages.csv").open(newline="", encoding="utf-8") as f:
                for stage in csv.DictReader(f):
                    sw.writerow(dict(device_id=device, approach=row["approach"], repeat=row["repeat"], **stage))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path("results"))
    p.add_argument("--resume", type=Path, help="resume one suite directory with the same options")
    p.add_argument("--device-id", default="host", help="actual executing client machine; never a simulated device name")
    p.add_argument("--approaches", nargs="+", choices=ALL_APPROACHES, default=list(APPROACHES))
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--seconds", type=float, default=60)
    p.add_argument("--mode", choices=["minute", "factory"], default="minute")
    p.add_argument("--factory-seconds", type=float, default=3600)
    p.add_argument("--warmup", type=int, default=2)
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--sample-interval", type=float, default=0.1)
    p.add_argument("--cooldown", type=float, default=1)
    p.add_argument("--seed", type=int, default=20261018)
    p.add_argument("--benchmarks", nargs="+", choices=["network","keys"], default=["network","keys"])
    p.add_argument("--keygen-warmup", type=int, default=1)
    p.add_argument("--keygen-batch", type=int, default=1000)
    p.add_argument("--mtu", type=int, default=1200, help="maximum QUIC UDP payload, not link IP MTU")
    p.add_argument("--max-pending-closes", type=int, default=64)
    payload = p.add_mutually_exclusive_group()
    payload.add_argument("--payload-bytes", type=int, default=0)
    payload.add_argument("--payload-file", type=Path)
    args = p.parse_args()
    args.duration = args.seconds if args.mode == "minute" else args.factory_seconds
    if (not all(math.isfinite(v) for v in (args.duration,args.timeout,args.sample_interval,args.cooldown))
            or args.runs < 1 or args.duration <= 0 or args.timeout <= 0 or args.warmup < 0 or args.keygen_warmup<0 or args.keygen_batch<1
            or not .01 <= args.sample_interval <= 1 or args.cooldown < 0
            or not 1200 <= args.mtu <= 65507 or args.max_pending_closes < 1
            or not re.fullmatch(r"[A-Za-z0-9_-]+", args.device_id)
            or not 0 <= args.payload_bytes <= 1073741824):
        p.error("invalid run count, timing, device ID, UDP size or payload")
    if args.payload_file:
        args.payload_file = args.payload_file.resolve()
        if not args.payload_file.is_file() or not 0 < args.payload_file.stat().st_size <= 1073741824:
            p.error("payload file must be nonempty and at most 1 GiB")
    args.approaches = list(dict.fromkeys(args.approaches))
    args.benchmarks = list(dict.fromkeys(args.benchmarks))
    settings = {k: str(v) if isinstance(v, Path) else v for k,v in vars(args).items()
                if k not in ("out", "resume")}
    if args.payload_file:
        settings["payload_sha256"] = hashlib.file_digest(args.payload_file.open("rb"), "sha256").hexdigest()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    root = args.resume.resolve() if args.resume else (args.out / ("factory_life" if args.mode == "factory" else "minute_runs") / stamp).resolve()
    if args.resume:
        manifest = json.loads((root / "manifest.json").read_text())
        if manifest["settings"] != settings:
            p.error("resume options must match the original suite settings")
        current_hashes = {file.name:hashlib.sha256(file.read_bytes()).hexdigest()
                          for file in Path(__file__).parent.glob("*.py")}
        current_versions = {name:importlib.metadata.version(name)
                            for name in ("aioquic", "cryptography", "psutil")}
        if manifest["source_sha256"] != current_hashes or manifest["dependencies"] != current_versions:
            p.error("source or dependencies changed; start a new suite to avoid mixing implementations")
        jobs = manifest["jobs"]
    else:
        root.mkdir(parents=True)
        rng = random.Random(args.seed)
        jobs = []
        # Randomized complete blocks: every repeat contains all selected approaches.
        for repeat in range(1, args.runs+1):
            block = args.approaches[:]
            rng.shuffle(block)
            jobs.extend(dict(approach=a, repeat=repeat) for a in block)
        freq = psutil.cpu_freq()
        manifest = dict(created_utc=stamp, settings=settings, jobs=jobs,
            python=sys.version, executable=sys.executable, platform=platform.platform(),
            machine=platform.machine(), processor=platform.processor(),
            cpu_logical=psutil.cpu_count(), cpu_physical=psutil.cpu_count(logical=False),
            cpu_frequency_mhz=freq._asdict() if freq else None, ram_bytes=psutil.virtual_memory().total,
            dependencies={n:importlib.metadata.version(n) for n in ("aioquic", "cryptography", "psutil")},
            source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in Path(__file__).parent.glob("*.py")})
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"Output: {root}\n{len(jobs)} scenarios/repeats × {len(args.benchmarks)} windows × {args.duration:g} s; setup and warm-up are additional.", flush=True)
    completed = set()
    if (root / "runs.csv").exists():
        with (root / "runs.csv").open(newline="", encoding="utf-8") as f:
            completed = {(r["approach"],int(r["repeat"])) for r in csv.DictReader(f)}
    keys_completed = set()
    if (root/"key_generation.csv").exists():
        with (root/"key_generation.csv").open(newline="",encoding="utf-8") as f:
            keys_completed={(r["approach"],int(r["repeat"])) for r in csv.DictReader(f)}
    try:
        for ordinal, job in enumerate(jobs, 1):
            print(f"[{ordinal}/{len(jobs)}] {args.device_id} {job['approach']} repeat {job['repeat']}", flush=True)
            if "network" in args.benchmarks and (job["approach"],job["repeat"]) not in completed:
                row = run_one(root, job, args, ordinal)
                append_csv(root / "runs.csv", row)
                print(f"  network: {row['completed_handshakes']} complete; {row['handshakes_per_minute']:.2f}/min; "
                      f"{row['failed_attempts']} failed; {row['deadline_censored']} boundary-censored", flush=True)
            if "keys" in args.benchmarks and (job["approach"],job["repeat"]) not in keys_completed:
                row=run_keys(root,job,args,ordinal)
                append_csv(root/"key_generation.csv",row)
                print(f"  keys: {row['completed_key_generation_operations']} complete operations; "
                      f"{row['generated_key_pairs']} pairs; {row['generated_symmetric_keys']} symmetric keys",flush=True)
            # Keep each sleep short so interruption and status remain responsive.
            remaining = args.cooldown
            while remaining > 0:
                pause = min(remaining, 1)
                time.sleep(pause)
                remaining -= pause
    except KeyboardInterrupt:
        print("Interrupted. Completed runs retained; resume with --resume and the same options.", flush=True)
    finally:
        if (root / "runs.csv").exists():
            export_device_files(root, args.device_id)
            from .summarize import summarize
            summarize(root / "runs.csv", root / "summary.csv", args.seed)
        if (root / "key_generation.csv").exists():
            from .summarize import summarize
            summarize(root / "key_generation.csv", root / "key_generation_summary.csv", args.seed)
        export_comparison(root)


if __name__ == "__main__":
    main()
```

## stls_experiment/scenarios.py

```python
"""The seven requested scenarios, with authentication and exchange kept explicit."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    name: str
    label: str
    cert_kind: str
    rsa_bits: int
    group: str
    stls: bool = False


SCENARIOS = {
    "quic_stls": Scenario("quic_stls", "QUIC with STLS", "ecdsa", 0, "secp256r1", True),
    **{f"quic_tls_rsa{bits}": Scenario(f"quic_tls_rsa{bits}", f"QUIC TLS RSA-{bits}",
         "rsa", bits, "secp256r1") for bits in (4096, 3072, 2048)},
    **{f"quic_tls_ecdhe_{curve}": Scenario(f"quic_tls_ecdhe_{curve}", f"QUIC TLS ECDHE-{curve}",
         "ecdsa", 0, curve) for curve in ("secp256r1", "secp384r1", "secp521r1")},
}
APPROACHES = tuple(SCENARIOS)
# Old entry points remain available but are not part of the requested seven.
SCENARIOS["quic_tls_rsa"] = Scenario("quic_tls_rsa", "Legacy RSA-2048", "rsa", 2048, "secp256r1")
SCENARIOS["quic_tls_ecdsa"] = Scenario("quic_tls_ecdsa", "Legacy ECDSA-P256", "ecdsa", 0, "secp256r1")
SCENARIOS["tcp_stls"] = Scenario("tcp_stls", "Legacy TCP STLS", "none", 0, "", True)
ALL_APPROACHES = tuple(SCENARIOS)


def scenario(name):
    try:
        return SCENARIOS[name]
    except KeyError as exc:
        raise ValueError(f"unknown scenario: {name}") from exc
```

## stls_experiment/server.py

```python
"""TCP/STLS or QUIC/TLS/STLS server used by the experiment runner."""
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import logging
import time
from pathlib import Path

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.tls import CipherSuite
from .protocol import (Credentials, ServerState, SessionCipher, ProtocolError,
                       digest, pack, unpack, require)
from .transport import ALPN, Channel, Counters, OnlineLogger, MeteredQuicServer
from .system import metric_pid, write_json
from .scenarios import APPROACHES, ALL_APPROACHES, scenario
from .tls_profile import configure_tls


async def run_server(args):
    profile = scenario(args.approach)
    metrics = Counters(window_path=args.window or args.ready.parent / "window.json")
    configure_tls(profile, metrics)
    creds = Credentials.from_dict(json.loads((args.provision / "server.json").read_text()))
    state = ServerState(creds)
    lock = asyncio.Lock()
    tasks = set()
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("w", newline="", encoding="utf-8", buffering=1) as output:
        writer = csv.DictWriter(output, fieldnames=["request_hash", "validation_s", "validation_cpu_s",
            "response_s", "response_cpu_s", "confirmation_s", "confirmation_cpu_s", "status", "error_type"])
        writer.writeheader()

        async def session(reader, stream_writer):
            channel = Channel(reader, stream_writer)
            stls = args.approach.endswith("stls")
            row = dict(request_hash="", validation_s="", validation_cpu_s="", response_s="", response_cpu_s="",
                       confirmation_s="", confirmation_cpu_s="", status="failed", error_type="")
            try:
                async with asyncio.timeout(args.timeout):
                    hello = await channel.receive()
                    row["request_hash"] = digest(hello)
                    if stls:
                        # One outstanding transaction per CID. No shared JSON DB writes.
                        async with lock:
                            start, cpu = time.perf_counter(), time.process_time()
                            body = state.validate_hello(hello)
                            row["validation_s"] = time.perf_counter() - start
                            row["validation_cpu_s"] = time.process_time() - cpu
                            start, cpu = time.perf_counter(), time.process_time()
                            response = state.make_server_hello(hello, body)
                            if not body.get("retry"):
                                metrics.add("stls_key_bundles", 1)
                            row["response_s"] = time.perf_counter() - start
                            row["response_cpu_s"] = time.process_time() - cpu
                            await channel.send(response)
                            finished = await channel.receive()
                            start, cpu = time.perf_counter(), time.process_time()
                            old_epoch = state.current.epoch
                            ack = state.finish(finished)
                            metrics.add("stls_commits", state.current.epoch - old_epoch)
                            row["confirmation_s"] = time.perf_counter() - start
                            row["confirmation_cpu_s"] = time.process_time() - cpu
                            await channel.send(ack)
                            session_creds = state.current
                    else:
                        start = time.perf_counter()
                        probe = unpack(hello)
                        require(probe.get("kind") == "READY" and len(probe.get("nonce", "")) == 64,
                                "invalid ready probe")
                        row["validation_s"] = time.perf_counter() - start
                        start = time.perf_counter()
                        response = pack(dict(kind="READY_ACK", nonce=probe["nonce"]))
                        row["response_s"] = time.perf_counter() - start
                        await channel.send(response)
                    row["status"] = "success"
                    # Log before optional payload. Timings exclude CSV serialization.
                    writer.writerow(row)
                    row = None
                    recv_cipher = SessionCipher(session_creds, "c2s") if stls else None
                    ack_cipher = SessionCipher(session_creds, "s2c") if stls else None
                    try:
                        raw_metadata = await channel.receive()
                        metadata = unpack(recv_cipher.decrypt(raw_metadata) if recv_cipher else raw_metadata)
                    except asyncio.IncompleteReadError:
                        return  # Normal handshake-only connection shutdown.
                    require(metadata.get("kind") == "TRANSFER", "invalid transfer header")
                    if stls:
                        state.authorize_transfer(session_creds)
                    size = metadata.get("size")
                    require(type(size) is int and 0 < size <= args.max_payload, "invalid transfer size")
                    total, checksum = 0, hashlib.sha256()
                    while total < size:
                        chunk = await channel.receive()
                        if recv_cipher:
                            chunk = recv_cipher.decrypt(chunk)
                        require(0 < len(chunk) <= size - total, "payload overflow")
                        total += len(chunk)
                        checksum.update(chunk)
                    require(checksum.hexdigest() == metadata.get("sha256"), "payload digest mismatch")
                    receipt = pack(dict(kind="TRANSFER_ACK", size=total, sha256=checksum.hexdigest()))
                    await channel.send(ack_cipher.encrypt(receipt) if ack_cipher else receipt)
            except (Exception,) as exc:
                if row is not None:
                    row["error_type"] = type(exc).__name__
                    writer.writerow(row)
                logging.debug("Rejected session: %s", type(exc).__name__)
            finally:
                stream_writer.close()
                # QUIC's stream adapter has no wait_closed implementation.
                if args.approach == "tcp_stls":
                    try:
                        await stream_writer.wait_closed()
                    except (ConnectionError, OSError):
                        pass

        def start_session(reader, writer):
            task = asyncio.create_task(session(reader, writer))
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        if args.approach == "tcp_stls":
            server = await asyncio.start_server(start_session, args.host, args.port)
            port = server.sockets[0].getsockname()[1]
        else:
            cert_kind = profile.cert_kind
            config = QuicConfiguration(is_client=False, alpn_protocols=ALPN,
                idle_timeout=args.timeout, cipher_suites=[CipherSuite.AES_256_GCM_SHA384],
                max_datagram_size=args.mtu, quic_logger=OnlineLogger(metrics))
            config.load_cert_chain(str(args.provision / (cert_kind + "-cert.pem")),
                                   str(args.provision / (cert_kind + "-key.pem")))
            transport, server = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: MeteredQuicServer(configuration=config, stream_handler=start_session, counts=metrics),
                local_addr=(args.host, args.port))
            port = transport.get_extra_info("sockname")[1]
        write_json(args.ready, dict(port=port, metric_pid=metric_pid()))
        print(f"READY {args.approach} {args.host}:{port}", flush=True)
        try:
            while not args.ready.with_suffix(".stop").exists():
                await asyncio.sleep(0.1)
        finally:
            server.close()
            for task in list(tasks):
                task.cancel()
            await asyncio.gather(*list(tasks), return_exceptions=True)
            output.flush()
            write_json(args.ready.parent / "server_totals.json", dict(
                server_udp_datagrams_sent=metrics.datagrams_tx,
                server_udp_datagrams_received=metrics.datagrams_rx,
                server_udp_bytes_sent=metrics.udp_tx, server_udp_bytes_received=metrics.udp_rx,
                server_quic_packets_sent=metrics.packets_tx,
                server_quic_packets_received=metrics.packets_rx,
                server_quic_packets_declared_lost=metrics.quic_lost,
                server_ephemeral_key_pairs_generated=metrics.ephemeral_key_pairs,
                server_stls_key_bundles_generated=metrics.stls_key_bundles,
                server_stls_symmetric_keys_generated=2*metrics.stls_key_bundles,
                server_stls_committed_epochs=metrics.stls_commits))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approach", choices=ALL_APPROACHES, required=True)
    p.add_argument("--provision", type=Path, required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--ready", type=Path, required=True)
    p.add_argument("--log", type=Path, required=True)
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--max-payload", type=int, default=1073741824)
    p.add_argument("--mtu", type=int, default=1200)
    p.add_argument("--window", type=Path, help="shared monotonic window JSON for this local experiment")
    a = p.parse_args()
    logging.basicConfig(level=logging.WARNING)
    try:
        asyncio.run(run_server(a))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
```

## stls_experiment/summarize.py

```python
"""Run-level summaries and reproducible bootstrap intervals; no pseudoreplication."""
import argparse
import csv
import random
import statistics
from collections import defaultdict
from pathlib import Path

METRICS = ("handshakes_per_minute", "completed_handshakes", "failed_attempts",
    "application_bytes_per_s", "udp_payload_bytes_per_s", "client_sampled_peak_rss_bytes",
    "server_sampled_peak_rss_bytes", "client_sampled_cpu_s", "server_sampled_cpu_s",
    "client_udp_datagrams_sent", "client_udp_datagrams_received", "server_udp_datagrams_sent",
    "server_udp_datagrams_received", "client_quic_packets_sent", "client_quic_packets_received",
    "server_quic_packets_sent", "server_quic_packets_received", "client_ephemeral_key_pairs_generated",
    "server_ephemeral_key_pairs_generated", "server_stls_symmetric_keys_generated",
    "completed_key_generation_operations", "generated_key_pairs", "generated_symmetric_keys",
    "key_generation_operations_per_minute", "key_pairs_per_minute", "symmetric_keys_per_minute",
    "mean_session_ready_s", "median_session_ready_s", "p95_session_ready_s")


def summarize(source: Path, destination: Path, seed=20261018):
    groups = defaultdict(list)
    with source.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            groups[row["device_id"], row["approach"], row.get("measurement_kind","independent_key_generation_capacity")].append(row)
    rng = random.Random(seed)
    with destination.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["device_id", "approach", "measurement_kind", "metric",
            "n_runs", "mean", "sd", "median", "min", "max", "bootstrap_mean_ci95_low",
            "bootstrap_mean_ci95_high"])
        writer.writeheader()
        for (device, approach, kind), rows in sorted(groups.items()):
            for metric in METRICS:
                values = [float(r[metric]) for r in rows if r.get(metric) not in (None, "")]
                if not values:
                    continue
                low = high = ""
                if len(values) > 1:
                    means = sorted(statistics.fmean(rng.choices(values, k=len(values))) for _ in range(5000))
                    low, high = means[124], means[4874]
                writer.writerow(dict(device_id=device, approach=approach, measurement_kind=kind,
                    metric=metric, n_runs=len(values), mean=statistics.fmean(values),
                    sd=statistics.stdev(values) if len(values)>1 else "", median=statistics.median(values),
                    min=min(values), max=max(values), bootstrap_mean_ci95_low=low,
                    bootstrap_mean_ci95_high=high))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("runs", type=Path)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seed", type=int, default=20261018)
    a = p.parse_args()
    summarize(a.runs, a.out, a.seed)


if __name__ == "__main__":
    main()
```

## stls_experiment/system.py

```python
"""Resolve process IDs in environments with a separately mounted Linux procfs."""
import os
import sys
import json
from pathlib import Path


def write_json(path, value):
    """Publish complete checkpoint/IPC JSON atomically, never a partial document."""
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def metric_pid():
    if sys.platform.startswith("linux"):
        try:
            target = os.readlink("/proc/self")
            if target.isdecimal():
                return int(target)
        except OSError:
            pass
    return os.getpid()
```

## stls_experiment/tls_profile.py

```python
"""Version-checked adapter for selecting and verifying real TLS ECDHE groups.

aioquic 1.2.0 has no public supported-groups configuration. This small adapter
replaces its TLS Context factory in each dedicated experiment subprocess. It
changes the allowed groups, observes the actual ServerHello and key creation,
and preserves the library's certificate/signature/Finished verification.
No fallback to another curve is permitted.
"""
import importlib.metadata
from aioquic import tls
from aioquic.buffer import Buffer

_ORIGINAL_CONTEXT = tls.Context
_GROUPS = dict(secp256r1=tls.Group.SECP256R1, secp384r1=tls.Group.SECP384R1,
               secp521r1=tls.Group.SECP521R1)


def configure_tls(profile, metrics=None):
    if importlib.metadata.version("aioquic") != "1.2.0":
        raise RuntimeError("TLS group adapter requires aioquic==1.2.0; revalidate before upgrading")
    if not profile.group:
        return
    expected = _GROUPS[profile.group]

    class ProfileContext(_ORIGINAL_CONTEXT):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._supported_groups = [expected]
            self.experiment_group = ""
            self.experiment_signature = ""

        def _client_send_hello(self, *args, **kwargs):
            result = super()._client_send_hello(*args, **kwargs)
            if len(self._ec_private_keys) != 1 or self._ec_private_keys[0].curve.name != profile.group:
                raise RuntimeError("client did not generate exactly the selected ECDHE key pair")
            if metrics:
                metrics.add("ephemeral_key_pairs", 1)
            return result

        def _client_handle_hello(self, input_buf, output_buf):
            copy = Buffer(data=input_buf.data_slice(0, input_buf.capacity))
            copy.seek(input_buf.tell())
            hello = tls.pull_server_hello(copy)
            if hello.key_share is None or hello.key_share[0] != expected:
                raise tls.AlertIllegalParameter("unexpected ECDHE group in ServerHello")
            self.experiment_group = profile.group
            return super()._client_handle_hello(input_buf, output_buf)

        def _client_handle_certificate_verify(self, input_buf):
            copy = Buffer(data=input_buf.data_slice(0, input_buf.capacity))
            copy.seek(input_buf.tell())
            signature = tls.pull_certificate_verify(copy)
            self.experiment_signature = tls.SignatureAlgorithm(signature.algorithm).name
            return super()._client_handle_certificate_verify(input_buf)

        def _server_handle_hello(self, *args, **kwargs):
            result = super()._server_handle_hello(*args, **kwargs)
            if len(self._ec_private_keys) != 1 or self._ec_private_keys[0].curve.name != profile.group:
                raise tls.AlertIllegalParameter("server selected an unexpected ECDHE group")
            self.experiment_group = profile.group
            if metrics:
                metrics.add("ephemeral_key_pairs", 1)
            return result

    tls.Context = ProfileContext
```

## stls_experiment/transport.py

```python
"""Bounded stream framing and public aioquic hooks for UDP byte measurement."""
from __future__ import annotations

import asyncio
import time
import json
from pathlib import Path
from dataclasses import dataclass

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.logger import QuicLogger, QuicLoggerTrace
from aioquic.asyncio.server import QuicServer
from .protocol import MAX_FRAME, ProtocolError

ALPN = ["stls-experiment-v1"]


@dataclass
class Counters:
    app_tx: int = 0
    app_rx: int = 0
    udp_tx: int = 0
    udp_rx: int = 0
    datagrams_tx: int = 0
    datagrams_rx: int = 0
    packets_tx: int = 0
    packets_rx: int = 0
    quic_lost: int = 0
    ephemeral_key_pairs: int = 0
    stls_key_bundles: int = 0
    stls_commits: int = 0
    tls_completed: bool = False
    tls_resumed: bool = False
    tls_complete_at: float = 0.0
    deadline: float = float("inf")
    start: float = 0.0
    window_path: Path | None = None
    window_loaded: bool = False
    aggregate: Counters | None = None

    def active(self, at=None):
        if self.window_path is not None and not self.window_loaded:
            try:
                window = json.loads(self.window_path.read_text())
                self.start, self.deadline = window["start_monotonic"], window["deadline_monotonic"]
                self.window_loaded = True
            except FileNotFoundError:
                return False  # Warm-up takes place before the window is published.
        return self.start <= (time.monotonic() if at is None else at) <= self.deadline

    def add(self, field, amount, at=None):
        # One timestamp per event, including its aggregate update. Checking the
        # clock twice could put the same event on opposite sides of the deadline.
        at = time.monotonic() if at is None else at
        if self.active(at):
            setattr(self, field, getattr(self, field) + amount)
            if self.aggregate is not None:
                self.aggregate.add(field, amount, at)


class Channel:
    def __init__(self, reader, writer, counters: Counters | None = None):
        self.reader, self.writer = reader, writer
        self.counts = counters if counters is not None else Counters()

    async def send(self, data: bytes) -> None:
        if not 0 < len(data) <= MAX_FRAME:
            raise ProtocolError("invalid frame length")
        packet = len(data).to_bytes(4, "big") + data
        self.writer.write(packet)
        self.counts.add("app_tx", len(packet))
        await self.writer.drain()

    async def receive(self) -> bytes:
        # readexactly handles TCP/QUIC fragmentation and raises on truncation.
        try:
            prefix = await self.reader.readexactly(4)
        except asyncio.IncompleteReadError as exc:
            self.counts.add("app_rx", len(exc.partial))
            raise
        self.counts.add("app_rx", 4)
        length = int.from_bytes(prefix, "big")
        if not 0 < length <= MAX_FRAME:
            raise ProtocolError("invalid frame length")
        try:
            data = await self.reader.readexactly(length)
        except asyncio.IncompleteReadError as exc:
            self.counts.add("app_rx", len(exc.partial))
            raise
        self.counts.add("app_rx", length)
        return data


class CountingTransport:
    def __init__(self, transport, counts: Counters):
        self.transport, self.counts = transport, counts

    def sendto(self, data, addr=None):
        at = time.monotonic()
        self.counts.add("udp_tx", len(data), at)
        self.counts.add("datagrams_tx", 1, at)
        return self.transport.sendto(data, addr)

    def __getattr__(self, key):
        return getattr(self.transport, key)


class CountingProtocol(QuicConnectionProtocol):
    def __init__(self, *args, counts: Counters, **kwargs):
        self.counts = counts
        super().__init__(*args, **kwargs)

    def connection_made(self, transport):
        super().connection_made(CountingTransport(transport, self.counts))

    async def wait_connected(self):
        # aioquic shields its internal waiter. Keep a task that retrieves its
        # eventual exception when the experiment deadline cancels this caller.
        # Real connection failures still propagate through the await below.
        task = asyncio.create_task(super().wait_connected())
        task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        await asyncio.shield(task)

    def datagram_received(self, data, addr):
        at = time.monotonic()
        self.counts.add("udp_rx", len(data), at)
        self.counts.add("datagrams_rx", 1, at)
        super().datagram_received(data, addr)

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.counts.tls_completed = True
            self.counts.tls_resumed = event.session_resumed
            self.counts.tls_complete_at = asyncio.get_running_loop().time()
        # Keep aioquic stream-reader delivery and connection termination intact.
        super().quic_event_received(event)


class OnlineTrace(QuicLoggerTrace):
    """Collect counters without retaining a growing in-memory qlog."""
    def __init__(self, *args, counts=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.counts = counts
        self.lost = 0
        self.sent = 0
        self.smoothed_rtt_ms = None

    def log_event(self, *, category, event, data):
        if category == "recovery" and event == "packet_lost":
            self.lost += 1
            if self.counts:
                self.counts.add("quic_lost", 1)
        if category == "transport" and event == "packet_sent":
            self.sent += 1
            if self.counts:
                self.counts.add("packets_tx", 1)
        if category == "transport" and event == "packet_received" and self.counts:
            self.counts.add("packets_rx", 1)
        if category == "recovery" and event == "metrics_updated":
            self.smoothed_rtt_ms = data.get("smoothed_rtt", self.smoothed_rtt_ms)


class OnlineLogger(QuicLogger):
    def __init__(self, counts=None):
        # Each configuration is used for exactly one connection.
        super().__init__()
        self.trace: OnlineTrace | None = None
        self.counts = counts

    def start_trace(self, is_client, odcid):
        self.trace = OnlineTrace(is_client=is_client, odcid=odcid, counts=self.counts)
        return self.trace

    def end_trace(self, trace):
        pass


class MeteredQuicServer(QuicServer):
    """Count each received/sent UDP datagram at the server socket exactly once."""
    def __init__(self, *args, counts, **kwargs):
        self.counts = counts
        super().__init__(*args, **kwargs)

    def connection_made(self, transport):
        super().connection_made(CountingTransport(transport, self.counts))

    def datagram_received(self, data, addr):
        at = time.monotonic()
        self.counts.add("udp_rx", len(data), at)
        self.counts.add("datagrams_rx", 1, at)
        super().datagram_received(data, addr)
```

## tests/test_automation.py

```python
"""Short real TCP/UDP integration runs; these are validation, not paper results."""
import csv
import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest
from stls_experiment.server import APPROACHES
from stls_experiment.provision import provision
from stls_experiment.scenarios import scenario

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("payload", [0, 32769])
def test_seven_approaches_and_csv_consistency(tmp_path, payload):
    command = [sys.executable, str(ROOT / "run_experiment.py"), "--runs", "1", "--seconds", "0.8",
        "--warmup", "1", "--cooldown", "0", "--sample-interval", "0.05", "--payload-bytes", str(payload),
        "--out", str(tmp_path)]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    suite = next(tmp_path.rglob("runs.csv"))
    rows = list(csv.DictReader(suite.open()))
    assert {r["approach"] for r in rows} == set(APPROACHES)
    assert len(rows) == 7
    for row in rows:
        folder = suite.parent / row["raw_folder"]
        attempts = list(csv.DictReader((folder/"attempts.csv").open()))
        traffic = list(csv.DictReader((folder/"connection_traffic.csv").open()))
        assert int(row["completed_handshakes"]) > 0
        assert int(row["failed_attempts"]) == 0
        assert int(row["completed_handshakes"]) == sum(a["status"] == "success" for a in attempts)
        assert int(row["attempts"]) == len(attempts)
        assert int(row["attempts"]) == int(row["completed_handshakes"]) + int(row["failed_attempts"]) + int(row["deadline_censored"])
        assert all(float(a["ready_at_s"]) <= .8 for a in attempts if a["status"] == "success")
        assert int(row["app_tx_bytes"]) == sum(int(t["app_tx_bytes"]) for t in traffic)
        assert int(row["app_rx_bytes"]) == sum(int(t["app_rx_bytes"]) for t in traffic)
        assert int(row["client_sampled_peak_rss_bytes"]) > 0
        assert int(row["server_sampled_peak_rss_bytes"]) > 0
        stages = list(csv.DictReader((folder/"stages.csv").open()))
        assert len(stages) == 4 * len(attempts)
        for attempt in attempts:
            if attempt["status"] == "success":
                subtotal = sum(float(attempt[k]) for k in ["stage1_transport_s", "stage2_exchange_s", "stage3_confirm_s"])
                assert subtotal == pytest.approx(float(attempt["total_ready_s"]), abs=1e-8)
                assert attempt["tls_resumed"] == "False"
        if row["approach"] == "tcp_stls":
            assert row["udp_tx_bytes"] == ""
        else:
            assert int(row["udp_tx_bytes"]) == sum(int(t["udp_tx_bytes"]) for t in traffic)
            assert int(row["udp_rx_bytes"]) == sum(int(t["udp_rx_bytes"]) for t in traffic)
            assert int(row["client_udp_datagrams_sent"]) == sum(int(t["datagrams_tx"]) for t in traffic)
            assert int(row["client_quic_packets_sent"]) == sum(int(t["quic_packets_sent"]) for t in traffic)
            assert int(row["client_quic_packets_received"]) == sum(int(t["quic_packets_received"]) for t in traffic)
            assert int(row["server_udp_datagrams_sent"])>0
            assert int(row["server_udp_datagrams_received"])>0
            assert int(row["server_quic_packets_sent"])>0
            assert int(row["server_quic_packets_received"])>0
            assert int(row["client_ephemeral_key_pairs_generated"])>=int(row["completed_handshakes"])
            assert int(row["server_ephemeral_key_pairs_generated"])>=int(row["completed_handshakes"])
            profile=scenario(row["approach"])
            for attempt in attempts:
                if attempt["status"]=="success":
                    assert attempt["negotiated_group"]==profile.group
                    assert int(attempt["peer_certificate_key_bits"])==(profile.rsa_bits if profile.cert_kind=="rsa" else 256)
                    assert attempt["signature_algorithm"]
            if profile.stls:
                assert int(row["server_stls_symmetric_keys_generated"])>=2*int(row["completed_handshakes"])
        if payload:
            assert int(row["payload_completions"]) > 0
            assert int(row["payload_bytes"]) == int(row["payload_completions"]) * payload
    capacities=list(csv.DictReader((suite.parent/"key_generation.csv").open()))
    assert len(capacities)==7
    for key in capacities:
        batches=list(csv.DictReader((suite.parent/key["keygen_raw_folder"]/"keygen_batches.csv").open()))
        count=int(key["completed_key_generation_operations"])
        assert sum(int(batch["completed_operations"]) for batch in batches)==count
        assert int(key["attempts"])==count+int(key["failed_operations"])+int(key["deadline_censored_operations"])
        if scenario(key["approach"]).stls:
            assert int(key["generated_symmetric_keys"])==2*count
            assert int(key["generated_key_pairs"])==0
        else:
            assert int(key["generated_key_pairs"])==count
            assert int(key["generated_symmetric_keys"])==0
    assert len(list(csv.DictReader((suite.parent/"comparison.csv").open())))==7


def test_cli_rejects_nan(tmp_path):
    result = subprocess.run([sys.executable, "run_experiment.py", "--seconds", "nan", "--out", str(tmp_path)],
                            cwd=ROOT, capture_output=True, timeout=15)
    assert result.returncode != 0
    assert not list(tmp_path.rglob("runs.csv"))


def test_timeout_is_failed_or_censored_and_never_success(tmp_path):
    provision(tmp_path / "provision")
    async def check():
        async def silent(reader, writer):
            try:
                await reader.read()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(silent, "127.0.0.1", 0)
        try:
            worker = await asyncio.create_subprocess_exec(sys.executable, "-m", "stls_experiment.client",
                "--approach", "tcp_stls", "--provision", str(tmp_path / "provision"),
                "--out", str(tmp_path / "worker"), "--port", str(server.sockets[0].getsockname()[1]),
                "--seconds", "0.3", "--timeout", "0.05", "--warmup", "0",
                cwd=ROOT, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(worker.communicate(), timeout=10)
            assert worker.returncode == 0, stdout.decode()+stderr.decode()
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(check())
    row = json.loads((tmp_path / "worker" / "worker_summary.json").read_text())
    assert row["completed_handshakes"] == 0
    assert row["failed_attempts"] >= 1
    assert row["deadline_censored"] == 1


def test_untrusted_certificate_is_rejected(tmp_path):
    from stls_experiment.run_experiment import wait_file, stop_process
    provision(tmp_path / "server_provision")
    provision(tmp_path / "wrong_trust")
    ready = tmp_path / "server_ready.json"
    with (tmp_path / "server.log").open("w") as log:
        server = subprocess.Popen([sys.executable, "-m", "stls_experiment.server", "--approach", "quic_tls_rsa",
            "--provision", str(tmp_path/"server_provision"), "--ready", str(ready), "--log", str(tmp_path/"stages.csv")],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            wait_file(ready, server, 10)
            result = subprocess.run([sys.executable, "-m", "stls_experiment.client", "--approach", "quic_tls_rsa",
                "--provision", str(tmp_path/"wrong_trust"), "--out", str(tmp_path/"client"), "--port",
                str(json.loads(ready.read_text())["port"]), "--seconds", "0.5", "--timeout", "1", "--warmup", "1"],
                cwd=ROOT, capture_output=True, text=True, timeout=15)
            assert result.returncode != 0
            assert not (tmp_path/"client"/"worker_summary.json").exists()
            assert "warm-up failed" in result.stderr
            assert "Future exception was never retrieved" not in result.stderr
        finally:
            ready.with_suffix(".stop").touch()
            stop_process(server)


def test_repeated_runs_and_resume_do_not_duplicate_results(tmp_path):
    command = [sys.executable, "run_experiment.py", "--runs", "2", "--seconds", "0.4",
        "--approaches", "tcp_stls", "--warmup", "0", "--cooldown", "0", "--out", str(tmp_path)]
    first = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert first.returncode == 0, first.stdout+first.stderr
    suite = next(tmp_path.rglob("runs.csv"))
    before = suite.read_bytes()
    raw_count = len(list((suite.parent/"raw").iterdir()))
    second = subprocess.run(command + ["--resume",str(suite.parent)], cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
    assert second.returncode == 0, second.stdout+second.stderr
    assert suite.read_bytes() == before
    assert len(list((suite.parent/"raw").iterdir())) == raw_count
    rows = list(csv.DictReader((suite.parent/"summary.csv").open()))
    count = next(r for r in rows if r["metric"] == "handshakes_per_minute")
    assert count["n_runs"] == "2"
    assert count["bootstrap_mean_ci95_low"] != ""
```

## tests/test_profiles.py

```python
"""Selection and boundary properties that could otherwise mislabel results."""
import json
import pytest
from aioquic import tls
from aioquic.buffer import Buffer
from stls_experiment.scenarios import APPROACHES, scenario
from stls_experiment.tls_profile import configure_tls
from stls_experiment.transport import Counters


def test_exactly_seven_default_profiles():
    assert len(APPROACHES)==7
    assert {scenario(n).rsa_bits for n in APPROACHES if scenario(n).cert_kind=="rsa"}=={2048,3072,4096}
    assert {scenario(n).group for n in APPROACHES if "ecdhe" in n}=={"secp256r1","secp384r1","secp521r1"}


def test_actual_wrong_server_hello_group_is_rejected():
    previous=tls.Context
    try:
        configure_tls(scenario("quic_tls_ecdhe_secp521r1"))
        context=tls.Context(is_client=True)
        assert context._supported_groups==[tls.Group.SECP521R1]
        output=Buffer(capacity=4096)
        hello=tls.ServerHello(random=b"R"*32, legacy_session_id=b"",
            cipher_suite=tls.CipherSuite.AES_256_GCM_SHA384, compression_method=0,
            key_share=(tls.Group.SECP256R1,b"X"*65), supported_version=tls.TLS_VERSION_1_3)
        tls.push_server_hello(output,hello)
        with pytest.raises(tls.AlertIllegalParameter,match="unexpected ECDHE group"):
            context._client_handle_hello(Buffer(data=output.data),Buffer(capacity=4096))
    finally:
        tls.Context=previous


def test_counter_window_and_warmup_exclusion(tmp_path,monkeypatch):
    path=tmp_path/"window.json"
    counter=Counters(window_path=path)
    now=[99.0]
    monkeypatch.setattr("stls_experiment.transport.time.monotonic",lambda:now[0])
    counter.add("packets_tx",1)
    assert counter.packets_tx==0
    path.write_text(json.dumps(dict(start_monotonic=100,deadline_monotonic=160)))
    counter.add("packets_tx",1)
    assert counter.packets_tx==0
    now[0]=100
    counter.add("packets_tx",1)
    now[0]=160
    counter.add("packets_tx",1)
    now[0]=160.00001
    counter.add("packets_tx",1)
    assert counter.packets_tx==2


def test_event_uses_one_timestamp_for_connection_and_aggregate(monkeypatch):
    times=iter([159.9999,160.0001])
    monkeypatch.setattr("stls_experiment.transport.time.monotonic",lambda:next(times))
    total=Counters(deadline=160)
    connection=Counters(deadline=160,aggregate=total)
    connection.add("packets_tx",1)
    assert total.packets_tx==connection.packets_tx==1
```

## tests/test_protocol.py

```python
"""Security and recovery properties that affect the validity of experiments."""
import asyncio
import copy
import json

import pytest
from cryptography.exceptions import InvalidTag
from stls_experiment.protocol import (ClientState, Credentials, ServerState,
    SessionCipher, ProtocolError, b64, digest, open_message, pack, seal, unpack)
from stls_experiment.transport import Channel


def pair():
    creds = Credentials.generate("device1")
    return ClientState(creds), ServerState(creds)


def exchange(client, server):
    ch = client.client_hello()
    sh = server.make_server_hello(ch, server.validate_hello(ch))
    fin = client.accept_server_hello(sh)
    ack = server.finish(fin)
    client.accept_ack(ack)
    return ch, sh, fin, ack


def test_rotates_every_success_without_unbounded_replay_history():
    client, server = pair()
    for epoch in range(1, 50):
        previous = client.current
        exchange(client, server)
        assert client.current == server.current
        assert client.current.epoch == epoch
        assert client.current.key1 != previous.key1
        assert client.current.key2 != previous.key2
        assert client.current.sid != previous.sid
        assert server.pending is None
        assert not any(isinstance(v, (list, set)) for v in vars(server).values())


def test_tamper_and_wrong_cid_do_not_change_server_state():
    client, server = pair()
    before = copy.deepcopy(vars(server))
    envelope = unpack(client.client_hello())
    envelope["cid"] = "other"
    with pytest.raises(ProtocolError):
        server.validate_hello(pack(envelope))
    envelope = unpack(client.client_hello())
    envelope["encrypted"] = b64(b"\x00" * 80)
    with pytest.raises(InvalidTag):
        server.validate_hello(pack(envelope))
    assert vars(server) == before


def test_sid_and_sequence_are_checked_even_with_valid_aead():
    client, server = pair()
    for changes in (dict(sid=b64(b"X"*32)), dict(session=4), dict(sequence=2)):
        body = dict(sid=b64(client.current.sid), nonce=b64(b"N"*32), session=0, sequence=0)
        body.update(changes)
        with pytest.raises(ProtocolError):
            server.validate_hello(seal(client.current, "CH", body))
    assert server.pending is None


def test_old_messages_rejected_after_next_epoch_starts():
    client, server = pair()
    old_ch, old_sh, old_fin, old_ack = exchange(client, server)
    exchange(client, server)
    with pytest.raises(ProtocolError):
        server.validate_hello(old_ch)
    with pytest.raises((InvalidTag, ProtocolError)):
        server.finish(old_fin)
    with pytest.raises(ProtocolError):
        client.accept_ack(old_ack)


@pytest.mark.parametrize("lost_message", ["SH", "FIN", "ACK"])
def test_lost_messages_recover_without_reprovisioning(lost_message):
    client, server = pair()
    ch = client.client_hello()
    sh = server.make_server_hello(ch, server.validate_hello(ch))
    if lost_message != "SH":
        fin = client.accept_server_hello(sh)
        if lost_message == "ACK":
            server.finish(fin)
    # Retry identical CH, get cached SH, verify again and finish successfully.
    assert client.client_hello() == ch
    retried_sh = server.make_server_hello(ch, server.validate_hello(ch))
    assert retried_sh == sh
    client.accept_ack(server.finish(client.accept_server_hello(retried_sh)))
    assert client.current == server.current
    assert client.current.epoch == 1
    exchange(client, server)
    assert client.current.epoch == 2


def test_bad_finished_keeps_pending_and_allows_correct_retry():
    client, server = pair()
    ch = client.client_hello()
    sh = server.make_server_hello(ch, server.validate_hello(ch))
    fin = client.accept_server_hello(sh)
    wrong = seal(server.pending, "FIN", dict(transcript="wrong", sequence=1))
    with pytest.raises(ProtocolError):
        server.finish(wrong)
    assert server.current.epoch == 0
    client.accept_ack(server.finish(fin))
    assert client.current.epoch == 1


def test_server_hello_bound_to_request_and_no_early_client_commit():
    client, server = pair()
    ch = client.client_hello()
    body = server.validate_hello(ch)
    sh = server.make_server_hello(ch, body)
    forged = open_message(client.current, "SH", sh)
    forged["request_hash"] = "wrong"
    with pytest.raises(ProtocolError):
        client.accept_server_hello(seal(client.current, "SH", forged))
    client.accept_server_hello(sh)
    assert client.current.epoch == 0
    assert server.current.epoch == 0


def test_data_nonce_sequence_and_direction_binding():
    creds = Credentials.generate("device1")
    tx, rx = SessionCipher(creds, "c2s"), SessionCipher(creds, "c2s")
    data = tx.encrypt(b"secret payload")
    assert rx.decrypt(data) == b"secret payload"
    with pytest.raises(ProtocolError):
        rx.decrypt(data)
    with pytest.raises(InvalidTag):
        SessionCipher(creds, "s2c").decrypt(data)


def test_fragmented_truncated_and_oversized_frames():
    async def check():
        reader = asyncio.StreamReader()
        channel = Channel(reader, None)
        task = asyncio.create_task(channel.receive())
        for byte in b"\x00\x00\x00\x05hello":
            reader.feed_data(bytes([byte]))
            await asyncio.sleep(0)
        assert await task == b"hello"
        reader.feed_data((100000).to_bytes(4,"big"))
        with pytest.raises(ProtocolError):
            await channel.receive()
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x00\x00\x00\x05ab")
        reader.feed_eof()
        with pytest.raises(asyncio.IncompleteReadError):
            await Channel(reader,None).receive()
    asyncio.run(check())


def test_direction_reflection_is_rejected():
    client, server = pair()
    with pytest.raises(ProtocolError):
        open_message(client.current, "SH", client.client_hello())


def test_transfer_cannot_be_replayed_in_same_epoch():
    client, server = pair()
    exchange(client, server)
    server.authorize_transfer(client.current)
    with pytest.raises(ProtocolError):
        server.authorize_transfer(client.current)
    previous = client.current
    exchange(client, server)
    with pytest.raises(ProtocolError):
        server.authorize_transfer(previous)
    server.authorize_transfer(client.current)
```

## requirements.txt

```text
# aioquic is pinned because explicit TLS curve selection uses a tested private-API adapter.
aioquic==1.2.0
cryptography>=42.0.0,<51
psutil>=5.9.8,<8
```

## requirements-dev.txt

```text
-r requirements.txt
pytest>=8,<10
```

## requirements-tested.txt

```text
# Direct dependency versions used for the supplied validation evidence.
aioquic==1.2.0
cryptography==50.0.2
psutil==7.2.2
```

## device_assumptions.json

```json
{
  "status": "Unverified assumptions transcribed from manuscript Table 6; not product specifications or measurements",
  "profiles": [
    {"device_id": "Tile_Mate", "mhz_assumption": 64},
    {"device_id": "Apple_AirTag", "mhz_assumption": 64},
    {"device_id": "Fitbit_Charge_5", "mhz_assumption": 96},
    {"device_id": "Xiaomi_Mi_Band_7", "mhz_assumption": 160},
    {"device_id": "Sensirion_SHT4x_board", "mhz_assumption": 48}
  ]
}
```
