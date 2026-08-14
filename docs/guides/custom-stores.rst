Custom stores
=============

Implement ``OtpStoreInterface``, ``ReplayStoreInterface``, or
``RecoveryCodeStoreInterface`` directly against Redis or a transactional
database. Preserve timing-safe digest comparison and every atomic invariant.
Document TTL precision, transaction isolation, conflict behavior, and whether
failed operations commit. Test concurrent correct submissions, concurrent wrong
submissions, monotonic advances, duplicate consume, and issue/verify races
against the real backing service.
