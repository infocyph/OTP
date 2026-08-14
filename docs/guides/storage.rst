Atomic storage
==============

Generic OTP
-----------

``issue`` atomically replaces the record. ``verifyAndConsume`` performs expiry
check, timing-safe digest comparison, successful deletion, or failed-attempt
decrement as one transition. It retains the original ``expiresAt`` value.

Replay
------

A relational ``consumeOnce`` is a unique insert. ``advance`` is a conditional
insert/update whose predicate is ``new_value > stored_value``. Do not implement
either as SELECT followed by INSERT/UPDATE outside one atomic statement or
transaction.

Recovery
--------

``consume`` and ``replace`` return the authoritative committed total, remaining,
and last-used state. A mutation result must not depend on a second metadata
query. Text factor IDs are bounded to 190 bytes; hashed Generic OTP storage
bindings are fixed-size SHA-256 hex values.
