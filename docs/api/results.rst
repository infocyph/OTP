Results and values
==================

``VerificationResult`` is created through invariant-preserving factories and
contains ``VerificationReason``, matched timestep or counter, ``nextCounter``,
drift, replay state, and successful verification time.

``RecoveryCodeGenerationResult`` contains the one-time plaintext batch and
committed counts. ``RecoveryCodeConsumptionResult`` contains consumed status and
the committed count/last-use state; it has no redundant string reason.

``EnrollmentPayload`` contains secret, URI, issuer, account label, and optional
SVG. Every secret, URI, and SVG value is sensitive.
