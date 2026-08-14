Recovery codes
==============

Recovery codes require a separate HMAC-SHA-256 key. The default batch is ten
12-character codes formatted ``XXXX-XXXX-XXXX``. Ambiguous characters are
excluded. Input accepts case differences, spaces, and hyphens.

Generation atomically replaces the active batch. Consumption returns the state
committed by that same atomic mutation; it never performs a post-consumption
metadata read. Custom alphabets are deduplicated and must provide at least 40
bits of entropy. Raw submitted input is capped at 512 bytes before normalization.
