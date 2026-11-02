#!/usr/bin/env python3
"""Compare validated OTP HTTP requests on matched Runwire 3 hosts (Python stdlib)."""
import argparse
import asyncio
import json
import math
import os
from pathlib import Path
import signal
import socket
import statistics
import subprocess
import tempfile
import time

EXPECTED = b'{"accepted":true,"replay_rejected":true,"ocra":true,"provisioning":true}'


def process_tree(pid):
    pending, result = [pid], []
    while pending:
        current = pending.pop()
        proc = Path('/proc') / str(current)
        try:
            status = (proc / 'status').read_text()
            stat = (proc / 'stat').read_text().split(') ', 1)[1].split()
            rss = int(next(line.split()[1] for line in status.splitlines() if line.startswith('VmRSS:')))
            ticks = int(stat[11]) + int(stat[12])
            fds = len(list((proc / 'fd').iterdir()))
            pending.extend(int(value) for value in (proc / 'task' / str(current) / 'children').read_text().split())
            result.append((current, rss / 1024, ticks, fds))
        except (OSError, StopIteration, IndexError):
            continue
    return result


async def request(reader, writer):
    writer.write(b'GET /otp HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n')
    await writer.drain()
    header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), timeout=5)
    if not header.startswith(b'HTTP/1.1 200 '):
        raise RuntimeError('Unexpected HTTP status: ' + repr(header))
    fields = dict(line.split(b':', 1) for line in header.lower().split(b'\r\n')[1:] if b':' in line)
    if b'content-length' in fields:
        body = await reader.readexactly(int(fields[b'content-length']))
    elif fields.get(b'transfer-encoding', b'').strip() == b'chunked':
        chunks = []
        while True:
            size = int((await reader.readline()).strip(), 16)
            if size == 0:
                await reader.readline()
                break
            chunks.append(await reader.readexactly(size))
            if await reader.readexactly(2) != b'\r\n':
                raise RuntimeError('Invalid chunk terminator')
        body = b''.join(chunks)
    else:
        raise RuntimeError('Response requires explicit framing')
    if body != EXPECTED:
        raise RuntimeError('Authentication response validation failed: ' + repr(body))
    return fields.get(b'connection', b'').strip() != b'close'


async def load(port, concurrency, duration, pid, warmup=False):
    connections = [await asyncio.open_connection('127.0.0.1', port) for _ in range(concurrency)]
    # Every connection and request path is ready before the measured interval.
    for reader, writer in connections:
        await request(reader, writer)
    start = time.monotonic()
    deadline = start + duration
    samples, ticks, latencies = [], {}, []
    completed = 0
    client_cpu = time.process_time()

    async def monitor():
        while time.monotonic() < deadline:
            tree = process_tree(pid)
            if len(tree) != 3:
                raise RuntimeError('Expected two live workers and their supervisor throughout load')
            samples.append((sum(p[1] for p in tree), sum(p[3] for p in tree)))
            for current, _, cpu, _ in tree:
                first, _ = ticks.get(current, (cpu, cpu))
                ticks[current] = (first, cpu)
            await asyncio.sleep(0.05)

    async def client(reader, writer):
        nonlocal completed
        count = 0
        try:
            while time.monotonic() < deadline:
                before = time.monotonic()
                keep_alive = await request(reader, writer)
                completed += 1
                count += 1
                if count % 20 == 0:
                    latencies.append((time.monotonic() - before) * 1000)
                if not keep_alive:
                    writer.close()
                    await writer.wait_closed()
                    reader, writer = await asyncio.open_connection('127.0.0.1', port)
        finally:
            writer.close()
            await writer.wait_closed()

    try:
        await asyncio.gather(monitor(), *(client(r, w) for r, w in connections))
    finally:
        for _, writer in connections:
            writer.close()
        await asyncio.gather(*(writer.wait_closed() for _, writer in connections), return_exceptions=True)
    elapsed = time.monotonic() - start
    cpu = sum(last - first for first, last in ticks.values()) / os.sysconf('SC_CLK_TCK')
    ordered = sorted(latencies)
    percentile = lambda p: ordered[min(len(ordered) - 1, math.ceil(len(ordered) * p) - 1)] if ordered else None
    result = {
        'successful_requests': completed, 'failed_requests': 0, 'timeouts': 0,
        'duration_seconds': elapsed, 'successful_rpm': completed / elapsed * 60,
        'latency_ms': {'p50': percentile(.5), 'p95': percentile(.95), 'p99': percentile(.99)},
        'server_cpu_percent': cpu / elapsed * 100,
        'client_cpu_percent': (time.process_time() - client_cpu) / elapsed * 100,
        'rss_initial_mb': samples[0][0], 'rss_final_mb': samples[-1][0],
        'rss_peak_mb': max(s[0] for s in samples),
        'rss_growth_mb': max(0, samples[-1][0] - samples[0][0]),
        'fd_peak_count': max(s[1] for s in samples), 'resource_samples': len(samples),
    }
    if not warmup and (result['rss_peak_mb'] > 192 or result['rss_growth_mb'] > 24
                       or result['fd_peak_count'] > 768 or (percentile(.99) or 0) > 1000):
        raise RuntimeError('HTTP host resource/latency budget exceeded: ' + json.dumps(result))
    return result


async def start_host(root, configuration, output_dir, label):
    ready = tempfile.TemporaryDirectory(prefix='otp-http-ready-')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    command = [configuration.php, '-d', 'opcache.enable_cli=1', str(Path(__file__).with_name('http-host.php')),
               '--autoload=' + str(root / 'vendor/autoload.php'), '--address=127.0.0.1:' + str(port),
               '--ready-dir=' + ready.name]
    log = (output_dir / (label + '-server.log')).open('w')
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                               preexec_fn=lambda: os.sched_setaffinity(0, configuration.server_cpus))
    host = (process, port, log, ready)
    try:
        for _ in range(400):
            if process.poll() is not None:
                raise RuntimeError('HTTP server exited: inspect ' + str(log.name))
            if len(list(Path(ready.name).glob('ready-*'))) == 2:
                await load(port, 8, configuration.warmup, process.pid, warmup=True)
                return host
            await asyncio.sleep(.05)
        raise RuntimeError('Both server workers must reach readiness')
    except BaseException:
        stop_host(host)
        raise


def stop_host(host):
    process, _, log, ready = host
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    log.close()
    ready.cleanup()


async def main(configuration):
    output = configuration.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    result = {'scope': 'HTTP/1.1 keep-alive, two Runwire 3 workers, shared integrity-protected SQLite; '
                       'Generic OTP generate/verify/replay, counter OCRA and provisioning parse on every request',
              'environment': {'php': subprocess.check_output([configuration.php, '-v'], text=True).splitlines()[0],
                              'os': os.uname().release, 'cpu_count': os.cpu_count(),
                              'server_cpus': configuration.server_cpus, 'client_cpus': sorted(os.sched_getaffinity(0))},
              'configuration': {k: str(v) if isinstance(v, Path) else v for k, v in vars(configuration).items()}}
    hosts = {}
    trials = {'baseline': {}, 'candidate': {}}
    try:
        for label in trials:
            hosts[label] = await start_host(getattr(configuration, label).resolve(), configuration, output, label)
        for concurrency in configuration.concurrency:
            for label in trials:
                trials[label][str(concurrency)] = []
            for trial in range(configuration.repetitions):
                order = ['baseline', 'candidate'] if trial % 2 == 0 else ['candidate', 'baseline']
                for label in order:
                    process, port, _, _ = hosts[label]
                    measured = await load(port, concurrency, configuration.duration, process.pid)
                    trials[label][str(concurrency)].append(measured)
                    print(label, 'c=' + str(concurrency), 'trial=' + str(trial + 1),
                          round(measured['successful_rpm']), 'RPM', flush=True)
        if configuration.soak_duration:
            process, port, _, _ = hosts['candidate']
            result['soak'] = await load(port, max(configuration.concurrency), configuration.soak_duration, process.pid)
    finally:
        for host in hosts.values():
            stop_host(host)
    accepted, comparisons = True, {}
    for label, workloads in trials.items():
        result[label] = {}
        for concurrency, values in workloads.items():
            rpms = [t['successful_rpm'] for t in values]
            result[label][concurrency] = {'trials': values, 'median_successful_rpm': statistics.median(rpms),
                                          'cv_percent': statistics.pstdev(rpms) / statistics.mean(rpms) * 100}
    for concurrency in result['baseline']:
        before, after = result['baseline'][concurrency], result['candidate'][concurrency]
        regression = (1 - after['median_successful_rpm'] / before['median_successful_rpm']) * 100
        stable = max(before['cv_percent'], after['cv_percent']) <= 2.5
        comparisons[concurrency] = {'regression_percent': regression, 'stable': stable,
                                    'passed': stable and regression <= 2}
        accepted &= comparisons[concurrency]['passed']
    result.update(comparisons=comparisons, passed=accepted)
    (output / 'http-acceptance.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(comparisons, indent=2), flush=True)
    if not accepted:
        raise SystemExit('HTTP acceptance requires stable trials and no more than 2% RPM regression')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--php', default='php')
    parser.add_argument('--duration', type=float, default=15)
    parser.add_argument('--soak-duration', type=float, default=0)
    parser.add_argument('--warmup', type=float, default=5)
    parser.add_argument('--repetitions', type=int, default=3)
    parser.add_argument('--concurrency', type=int, nargs='+', default=[1, 8, 32])
    arguments = parser.parse_args()
    if not (arguments.duration >= 1 and (arguments.soak_duration == 0 or arguments.soak_duration >= 300) and arguments.warmup >= 1 and arguments.repetitions >= 3
            and all(1 <= n <= 128 for n in arguments.concurrency)):
        parser.error('Positive durations, at least three trials and bounded concurrency are required')
    allowed_cpus = sorted(os.sched_getaffinity(0))
    arguments.server_cpus = allowed_cpus[:2]
    os.sched_setaffinity(0, allowed_cpus[2:] or allowed_cpus)
    asyncio.run(main(arguments))
