#!/usr/bin/env python3
"""Calibrate and compare four-worker SQLite trials without dropping measurements."""
import argparse
import datetime
import json
import math
import os
from pathlib import Path
import signal
import statistics
import subprocess

ORDER = (0, 1, 1, 0, 0, 1, 1, 0)
DURATION = 30
SPREAD_LIMIT = 5
REGRESSION_LIMIT = 2
WORKERS = 4


def cpu_placement():
    groups = {}
    for cpu in sorted(os.sched_getaffinity(0)):
        topology = Path('/sys/devices/system/cpu') / f'cpu{cpu}' / 'topology'
        try:
            key = ((topology / 'physical_package_id').read_text().strip(),
                   (topology / 'core_id').read_text().strip())
        except OSError:
            key = ('logical', str(cpu))
        groups.setdefault(key, []).append(cpu)
    cores = list(groups.values())
    preferred = [group[0] for group in cores]
    siblings = [cpu for group in cores for cpu in group[1:]]
    selected = (preferred + siblings)[:WORKERS]
    if not selected:
        raise RuntimeError('No allowed CPUs for SQLite benchmark')
    return selected, cores


def measure(php, harness, root, release, cpus, output):
    autoload = root / 'vendor/autoload.php'
    command = [php, '-d', 'auto_prepend_file=' + str(autoload), str(harness),
               '--autoload=' + str(autoload), '--release=' + release,
               '--duration=' + str(DURATION), '--stable', '--workload=concurrent-verify',
               '--concurrent-trial']
    with output.with_suffix('.log').open('w') as log:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True,
                                   start_new_session=True,
                                   preexec_fn=lambda: os.sched_setaffinity(0, cpus))
        try:
            stdout, _ = process.communicate(timeout=90)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
    output.write_text(stdout)
    if process.returncode:
        raise RuntimeError(f'SQLite trial failed: {output.with_suffix(".log")}')
    trial = json.loads(stdout)
    m = trial['measurement']
    if (trial['duration'] != DURATION or trial['concurrency'] != WORKERS
            or trial['stability_limit'] != SPREAD_LIMIT
            or trial['warmup_seconds'] != 5
            or trial['environment']['release'] != release
            or m['failed'] or m['successful'] <= 0 or m['attempted'] != m['successful']
            or m['elapsed'] < DURATION or not m['latencies']
            or any(m[key] is None for key in ('memory_start_mb', 'memory_end_mb', 'memory_peak_mb'))):
        raise RuntimeError(f'Invalid SQLite trial: {output}')
    if not math.isclose(m['successful_rpm'], m['successful'] / m['elapsed'] * 60, rel_tol=1e-9):
        raise RuntimeError(f'Inconsistent SQLite RPM: {output}')
    return trial


def aggregate(trials, cpus, cores):
    if len(trials) != 4 or any(t['environment'] != trials[0]['environment'] for t in trials):
        raise RuntimeError('Four trials with identical environment metadata required')
    measurements = [t['measurement'] for t in trials]
    rpms = [m['successful_rpm'] for m in measurements]
    median = statistics.median(rpms)
    spread = (max(rpms) - min(rpms)) / median * 100
    stable = spread <= SPREAD_LIMIT
    latencies = sorted(value for m in measurements for value in m['latencies'])
    elapsed = sum(m['elapsed'] for m in measurements)
    starts = [m['memory_start_mb'] for m in measurements]
    ends = [m['memory_end_mb'] for m in measurements]
    attempted = sum(m['attempted'] for m in measurements)
    successful = sum(m['successful'] for m in measurements)
    failed = sum(m['failed'] for m in measurements)
    return {
        'schema_version': 1,
        'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'environment': dict(trials[0]['environment'], stable=stable),
        'workloads': [{
            'name': 'generic-otp-concurrent-verification',
            'type': 'persistent-worker',
            'metadata': {
                'operation': 'four persistent workers performing GenericOtp::generate + verify',
                'backend': 'CacheLayer SQLite authoritative state',
                'runwire_context': 'absent',
                'queue': 'synchronized warmup and common measurement deadline',
                'backend_connections': WORKERS,
                'memory_measurement': 'parent and all ready workers RSS sampled every 10ms during load',
                'duration_per_repetition_seconds': DURATION,
                'soak_duration_seconds': DURATION * len(trials),
                'stability_spread_limit_percent': SPREAD_LIMIT,
                'warmup_seconds': trials[0]['warmup_seconds'],
                'allowed_cpus': cpus,
                'cpu_core_groups': cores,
                'trial_successful_rpm': rpms,
            },
            'repetitions': len(trials),
            'warmup_operations': trials[0]['warmup_operations_minimum'],
            'duration_seconds': DURATION * len(trials),
            'concurrency': WORKERS,
            'result': {
                'attempted_operations': attempted,
                'successful_operations': successful,
                'failed_operations': failed,
                'timeouts': 0,
                'successful_rpm': round(median, 5),
                'error_rate': failed / attempted,
                'latency_ms': {
                    'minimum': latencies[0], 'maximum': latencies[-1],
                    'average': statistics.mean(latencies),
                    **{f'p{p}': latencies[math.ceil(len(latencies) * p / 100) - 1]
                       for p in (50, 95, 99)},
                },
                'cpu': {'average_percent': sum(m['cpu_seconds'] for m in measurements) / elapsed * 100,
                        'peak_percent': None},
                'memory': {'average_mb': statistics.mean(starts + ends),
                           'peak_mb': max(m['memory_peak_mb'] for m in measurements),
                           'growth_mb': max(0, max(end - start for start, end in zip(starts, ends)))},
                'stability': {'status': 'stable' if stable else 'unstable',
                              'spread_percent': round(spread, 5)},
            },
        }],
    }


def main(args):
    output = args.output.resolve()
    raw = output / 'sqlite-trials'
    raw.mkdir(parents=True, exist_ok=True)
    cpus, cores = cpu_placement()
    print(f'SQLite affinity: {cpus}; physical core groups: {cores}', flush=True)
    baseline = (args.baseline.resolve(), args.baseline_release)
    candidate = (args.candidate.resolve(), args.candidate_release)
    for phase, arms in (
        ('aa', (('aa-baseline-a', baseline), ('aa-baseline-b', baseline))),
        ('ab', (('baseline-concurrent', baseline), ('candidate-concurrent', candidate))),
    ):
        trials = [[], []]
        for index, arm in enumerate(ORDER):
            label, (root, release) = arms[arm]
            trial = measure(args.php, args.harness.resolve(), root, release, cpus,
                            raw / f'{phase}-{index + 1:02d}-{label}.json')
            trials[arm].append(trial)
            print(f'{phase} {label} trial {len(trials[arm])}: '
                  f'{trial["measurement"]["successful_rpm"]:.2f} RPM', flush=True)
        reports = [aggregate(samples, cpus, cores) for samples in trials]
        before, after = [report['workloads'][0]['result'] for report in reports]
        if any({k: v for k, v in report['environment'].items() if k not in ('stable', 'release')}
               != {k: v for k, v in reports[0]['environment'].items() if k not in ('stable', 'release')}
               for report in reports):
            raise RuntimeError('Paired SQLite runtime metadata differs')
        for (label, _), report in zip(arms, reports):
            (output / f'{label}.json').write_text(json.dumps(report, indent=2) + '\n')
        regression = (1 - after['successful_rpm'] / before['successful_rpm']) * 100
        print(f'{phase}: regression {regression:.2f}%, spread '
              f'{before["stability"]["spread_percent"]:.2f}% / '
              f'{after["stability"]["spread_percent"]:.2f}%', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'harness', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--baseline-release', required=True)
    parser.add_argument('--candidate-release', required=True)
    parser.add_argument('--php', default='php')
    main(parser.parse_args())
