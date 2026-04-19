Benchmarks
==========

The project includes a ``phpbench`` configuration and a starter benchmark suite under ``benchmarks/``.

Available commands
------------------

Run the default aggregate report:

.. code-block:: bash

   composer bench:run

Run a quicker local iteration:

.. code-block:: bash

   composer bench:quick

Render the chart-style console report:

.. code-block:: bash

   composer bench:chart

What is benchmarked
-------------------

The starter suite in ``benchmarks/OtpBench.php`` covers:

- TOTP generation
- TOTP verification
- TOTP verification with replay state
- HOTP generation
- HOTP verification
- OCRA generation
- OCRA verification
- Generic OTP generation
- Generic OTP verification

Notes
-----

- Benchmarks should be treated as comparative measurements, not absolute performance guarantees.
- For stable numbers, prefer running on a quiet machine with repeated iterations.
- Replay-aware benchmarks create fresh in-memory state to avoid polluted runs.

Extending the suite
-------------------

Add more ``*Bench.php`` files under ``benchmarks/``.

The current benchmark config uses:

- ``runner.path = benchmarks``
- ``runner.file_pattern = *Bench.php``
- attribute-based benchmark discovery
