Replay protection
=================

``ReplayStoreInterface`` contains only two contractually atomic operations:

``consumeOnce(namespace, factorId, token, ttl)``
   Insert a token once; exactly one concurrent caller succeeds.

``advance(namespace, factorId, value, ttl)``
   Insert/update only when ``value`` is greater than current state.

There is no read/write fallback. A factor ID must uniquely identify one factor,
suite, secret version, and counter generation. ``InMemoryReplayStore`` is
process-local test/example infrastructure and is unsuitable for distributed or
high-cardinality production use.
