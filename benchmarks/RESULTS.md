# Benchmark comparison

Recorded on 2026-08-14 with PHP 8.4.24, PHPBench 1.7.0, no Xdebug, and no
OPcache. Both runs used 10 revolutions and 3 iterations. The baseline was the
committed pre-redesign tree (`e5b896d`) in an isolated temporary checkout; the
updated run used `composer ic:bench:quick`.

These quick results are regression signals, not stable hardware-independent
performance guarantees. Store implementations and persistence latency will
dominate the in-memory timings in production.

| Shared subject | Before | After | Change |
| --- | ---: | ---: | ---: |
| Generic OTP issue | 4.640 µs | 2.506 µs | -46.0% |
| Generic OTP verify | 2.333 µs | 1.394 µs | -40.2% |
| Generic OTP malformed | 0.206 µs | 0.200 µs | -2.9% |
| HOTP generate | 3.444 µs | 1.494 µs | -56.6% |
| HOTP verify | 12.215 µs | 3.606 µs | -70.5% |
| HOTP invalid | 15.758 µs | 6.994 µs | -55.6% |
| OCRA generate | 6.606 µs | 6.612 µs | +0.1% |
| OCRA verify | 19.648 µs | 14.858 µs | -24.4% |
| OCRA invalid | 12.300 µs | 9.288 µs | -24.5% |
| TOTP generate | 1.500 µs | 1.094 µs | -27.1% |
| TOTP verify | 17.759 µs | 3.500 µs | -80.3% |
| TOTP invalid | 13.500 µs | 5.094 µs | -62.3% |
| TOTP malformed | 8.188 µs | 0.994 µs | -87.9% |
| TOTP replay accepted | 17.604 µs | 4.659 µs | -73.5% |
| TOTP replay rejected | 12.616 µs | 3.400 µs | -73.1% |

The redesigned suite also records 32 additional subjects for algorithm,
window/look-ahead, OCRA input mode, recovery-code, provisioning/QR, and secret
utility coverage. OCRA generation is intentionally flat; its correctness fixes
did not introduce a measurable regression in this quick run. QR rendering
remains a separate millisecond-scale subject so it does not distort URI costs.
