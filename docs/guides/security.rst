Security model
==============

OTP arithmetic is only one part of an authentication system. This package
defines calculation, validation, provisioning, and atomic state boundaries.
Applications must supply identity policy, secure persistence, rate limiting,
delivery, session transitions, audit, and recovery controls.

Threat model
------------

Plan for:

* online guessing of short decimal codes;
* replay and concurrent duplicate requests;
* stolen databases and logs;
* leaked provisioning pages or QR images;
* compromised email/SMS delivery;
* account and factor enumeration;
* clock drift and rollback;
* counter rollback;
* key/secret reuse across purposes;
* stale replicas and non-atomic stores;
* session fixation after successful verification; and
* abuse of recovery and enrollment workflows.

Secret storage
--------------

Encrypt HOTP, TOTP, and OCRA secrets at rest with managed, access-controlled
keys. Restrict decryption to the verification path and minimize plaintext
lifetime. Database hashing is insufficient because verification needs the
secret.

Do not log:

* Base32 or raw factor secrets;
* Generic OTP or recovery HMAC keys;
* generated or submitted OTP/recovery values;
* provisioning URIs;
* QR SVG;
* OCRA PIN/session/challenge data when business-sensitive; or
* unredacted storage/replay identifiers.

``SensitiveParameter`` attributes reduce accidental PHP stack-trace disclosure
for annotated inputs. They do not sanitize application logs, telemetry,
exceptions, or database traces.

Purpose-separated HMAC keys
---------------------------

Generic OTP and recovery codes use mandatory HMAC-SHA-256 keys. Use a separate
random key for each purpose and environment:

.. code-block:: php

   $genericOtpKey = random_bytes(32);
   $recoveryCodeKey = random_bytes(32);

Keep keys in a KMS, HSM-backed secret service, or equivalent protected
configuration. Rotating a key invalidates all digests created with it, so plan a
versioned key rollout or intentional global invalidation.

Online guessing controls
------------------------

OTP code spaces are small. Package attempt counters cover one Generic OTP
record only and are not a full rate limiter. Apply layered limits:

* endpoint/request rate;
* account/factor rate;
* destination rate for delivery;
* IP/network rate;
* device/session rate;
* resend frequency; and
* daily enrollment/recovery limits.

Rate-limit malformed inputs too. Use delays or lockouts carefully to avoid
turning known accounts into denial-of-service targets.

Atomicity and replay
--------------------

Authentication-critical transitions must be atomic. A valid code accepted by
two concurrent requests is a replay vulnerability. Use a shared, fail-closed
CacheLayer backend for Generic OTP, TOTP, HOTP, and OCRA. CacheLayer must own a
lock provider in the same coordination domain; OTP obtains it from the cache and
rejects fail-open, unsigned, tiered/non-authoritative, or lock-incapable state
configuration. Recovery codes continue to use an application-provided atomic
persistence contract.

Factor IDs must include secret and moving-factor generation. Rotating a secret
without changing its factor ID can let new state conflict with old state;
resetting state under a reused ID can also reopen old credentials.

Transport and browser handling
------------------------------

Use TLS for every enrollment, delivery callback, and verification request.
Enrollment responses should be authenticated, non-cacheable, protected from
cross-site request forgery as applicable, and omitted from analytics/session
replay tooling. Apply a restrictive content security policy when embedding SVG.

Do not place OTP values in URLs because URLs commonly reach browser history,
reverse proxies, referrers, and access logs.

TOTP time
---------

Use monitored NTP synchronization on every verifier. Keep acceptance windows
small and explicit. Do not silently widen windows in response to failures.
Clock rollback can interact with replay TTL; monotonic replay state must remain
authoritative.

HOTP counters
-------------

Persist ``nextCounter`` after success and never decrement it. Bound
resynchronization. Investigate repeated large offsets. Counter reset requires a
new factor/moving-factor generation and replay ID.

Generic OTP delivery
--------------------

Bind a code to a random flow ID and purpose, not only an account. Use resend
cooldowns and decide whether resend replaces the current code. Protect provider
credentials and webhook endpoints. A successful OTP proves access to the
delivery channel at that moment; it does not prove a broader identity claim.

SMS is vulnerable to number reassignment, forwarding, malware, and carrier
attacks. Select channels according to the application's threat model.

OCRA challenges
---------------

Generate unpredictable server challenges where freshness matters and consume
them atomically. Canonically encode transaction fields. Never let displayed
transaction data differ from the bytes used to create the response. Time and
counter components do not eliminate the need for application authorization.

Recovery
--------

Recovery often bypasses strong factors and deserves equal or stronger controls.
Display recovery codes once, notify on use, rate-limit aggressively, and define
whether use triggers session invalidation or factor review. Regeneration
invalidates the prior complete batch.

Provisioning and rotation
-------------------------

URI, SVG, and ``EnrollmentPayload`` contain plaintext secret material. Store only
what is required, prove enrollment before activation, and delete abandoned
pending factors. During rotation, give old and new generations independent
replay IDs and enforce the exclusive overlap boundary.

Error handling
--------------

Configuration errors throw ``InvalidArgumentException``. Normal credential
failures return structured reasons. Storage failures propagate. At the public
boundary:

* fail closed on infrastructure errors;
* return generic authentication failures;
* avoid exposing malformed/mismatch/replay distinctions unless necessary;
* log only redacted operational context; and
* never retry a mutation after an unknown commit outcome without an
  idempotency/reconciliation strategy.

Session completion
------------------

After OTP success, rotate the session identifier, bind the authenticated state
to the intended account and flow, enforce any step-up policy in the application,
and prevent reuse of pre-authentication sessions. The package does not perform
these actions.

Audit
-----

Useful redacted events include enrollment started/completed/abandoned, factor
verified, replay rejected, recovery used/regenerated, rotation activated, and
factor revoked. Record factor generation and coarse reason without secrets,
codes, digests, provisioning payloads, or unnecessary personal data.

Security review checklist
-------------------------

Before launch, verify:

#. secrets and HMAC keys are purpose-separated and protected;
#. all production stores pass real concurrent race tests;
#. replay is enabled for authentication endpoints;
#. factor IDs change across secret/counter generations;
#. time is synchronized and windows are minimal;
#. every request path is rate-limited;
#. provisioning responses cannot be cached or logged;
#. recovery policy is documented and tested;
#. successful authentication rotates session state;
#. exceptions fail closed without sensitive output; and
#. key/secret compromise runbooks exist.
