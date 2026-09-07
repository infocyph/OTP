Security model
==============

OTP arithmetic is only one part of an authentication system. This package
defines calculation, validation, provisioning, WebAuthn ceremony integration,
and atomic state boundaries. Applications must supply identity policy, secure
persistence, rate limiting, delivery, session transitions, audit, and recovery
controls.

Threat model
------------

Plan for:

* online guessing of short codes and human responses;
* replay and concurrent duplicate requests;
* stolen databases and logs;
* leaked provisioning pages or QR images;
* compromised email/SMS delivery;
* account and factor enumeration;
* clock drift and rollback;
* counter rollback;
* key/secret reuse across purposes;
* stale replicas and non-atomic stores;
* AOTP verifier/challenge relay, context confusion, and blind-signing clients;
* repeated GridOTP visual observations;
* WebAuthn origin/RP misconfiguration and stale credential records;
* compromise of legacy MobileOTP Init-Secrets/PINs;
* session fixation after successful verification; and
* abuse of recovery and enrollment workflows.

Secret and credential storage
-----------------------------

Encrypt HOTP, TOTP, OCRA, GridOTP, and MobileOTP verifier secrets at rest with
managed, access-controlled keys. Restrict decryption to the verification path and
minimize plaintext lifetime. Database hashing is insufficient because
verification needs those values.

AOTP is asymmetric: the verifier stores only the enrolled public key. Protect
the private key on the client/device and prefer hardware-backed storage when the
application controls the client. A server that only verifies AOTP should never
receive the private key. OTP clears temporary decoded private-key copies created
inside ``AOTP::respond()`` with ``sodium_memzero()``, but the caller still owns
and must protect the original encoded key string and any copies made outside OTP.

Passkeys are WebAuthn credentials. The authenticator owns the private key; the
application persistently stores the serialized ``CredentialRecord`` returned by
``PasskeyResult``. That record contains authentication-critical public-key,
counter, backup, transport, and user-handle state. Store it in an authoritative
durable database and persist the updated record after every successful assertion.
CacheLayer is only the short-lived passkey ceremony store.

Do not log:

* Base32/raw factor, GridOTP, or MobileOTP secrets/PINs;
* AOTP private keys, challenge context/nonces, or signatures;
* Passkey ceremony options, browser credential JSON, CredentialRecord JSON, or
  raw user handles;
* Generic OTP or recovery HMAC keys;
* generated or submitted OTP/recovery/GridOTP values;
* provisioning URIs;
* QR SVG;
* OCRA PIN/session/challenge data when business-sensitive; or
* unredacted storage/replay identifiers.

``SensitiveParameter`` attributes reduce accidental PHP stack-trace disclosure
for annotated inputs. Secret-bearing result/value objects also provide redacted
debug representations. Neither mechanism sanitizes application logs, telemetry,
custom serialization, exceptions assembled by application code, or database
traces.

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

Short OTP spaces remain guessable. Package attempt counters cover one Generic
OTP or GridOTP record only and are not a full rate limiter. Apply layered limits:

* endpoint/request rate;
* account/factor rate;
* destination rate for delivery;
* IP/network rate;
* device/session rate;
* resend frequency; and
* daily enrollment/recovery limits.

Rate-limit malformed inputs too. Passkey and AOTP signatures are not short
passwords, but their endpoints still need abuse/DoS controls. Use delays or
lockouts carefully to avoid turning known accounts into denial-of-service
targets.

Atomicity and replay
--------------------

Authentication-critical transitions must be atomic. A valid credential accepted
by two concurrent requests is a replay vulnerability. Use a shared, fail-closed,
payload-integrity protected, authoritative CacheLayer backend for package-owned
authentication state. Tiered/non-authoritative or fail-open authentication state
is rejected.

TOTP, HOTP, OCRA, MobileOTP, and AOTP prefer CacheLayer 3.3 native atomic state
where their transition maps cleanly to CAS/set-if-absent. Backends without native
atomics require the coordinated lock fallback. Atomic capability selection is
not runtime failover: once an atomic mutation is selected, an exception
propagates and is never retried through a lock after an unknown commit outcome.

``GenericOtp`` and ``GridOTP`` remain lock-based because issuance/replacement,
attempt counts, expiry, integrity, consumption, and deletion are multi-field
state machines. ``Passkey`` also requires a coordinated lock because its stored
ceremony type/options/user binding/expiry/consumed marker must transition as one
unit.

AOTP first reserves an issued challenge and then atomically consumes that exact
reservation after signature verification. Signature validity is checked before a
consumed reservation is exposed as replay, so an invalid signer receives
``Mismatch`` rather than learning whether a valid signer already used the
challenge. Passkey successful ceremonies retain a consumed marker through the
original TTL so duplicate assertions can be reported as replay instead of
indistinguishable misses.

Factor IDs must include secret/key and moving-factor generation. Rotating a
secret without changing its factor ID can let new state conflict with old state;
resetting state under a reused ID can also reopen old credentials. Passkey
ceremony bindings should instead be flow-specific random/unique identifiers;
durable passkey credential IDs come from WebAuthn.

Transport and browser handling
------------------------------

Use TLS for every enrollment, delivery callback, and verification request.
Enrollment responses should be authenticated, non-cacheable, protected from
cross-site request forgery as applicable, and omitted from analytics/session
replay tooling. Apply a restrictive content security policy when embedding SVG.
Do not place OTP values or WebAuthn credential payloads in URLs.

Passkey/WebAuthn origins must be explicit. ``Passkey`` requires an RP ID and an
allowed-origin list; exact origins are the default and non-local HTTP origins are
rejected. Only enable subdomain-origin acceptance when the relying party owns
and secures those subdomains. Do not derive allowed origins from untrusted Host,
Origin, proxy, or request parameters.

TOTP, AOTP, and MobileOTP time
-----------------------------

Use monitored NTP synchronization on every verifier. AOTP signing clients also
need a trustworthy local clock because ``AOTP::respond()`` refuses challenges
before ``issuedAt`` and at/after ``expiresAt``. Do not disable or bypass that
check to compensate for clock problems.

Keep TOTP/MobileOTP acceptance windows small and explicit. Do not silently widen
windows in response to failures. Clock rollback can interact with replay TTL;
monotonic replay state must remain authoritative.

MobileOTP's established protocol uses a ten-second step, a 16-hex-character
Init-Secret, a four-digit PIN, MD5, and a six-hex-character output. OTP preserves
that calculation only for compatibility. The default verification window is
zero and the maximum explicit tolerance is the historical ±3-minute range.
Prefer TOTP, AOTP, or Passkey for new deployments.

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
SMS remains vulnerable to number reassignment, forwarding, malware, and carrier
attacks.

OCRA challenges
---------------

Generate unpredictable server challenges where freshness matters and consume
them atomically. Canonically encode transaction fields. Never let displayed
transaction data differ from the bytes used to create the response. Time and
counter components do not eliminate the need for application authorization.

AOTP challenges and phishing resistance
---------------------------------------

AOTP signs a canonical challenge containing ID, nonce, audience, mandatory
context, issuance, and expiry. The server reservation is keyed from the complete
signed challenge, not only the challenge ID. Challenge context cannot be empty.
Audience values reject whitespace/control characters and context rejects control
characters to reduce ambiguous identifiers and display/log injection.

``AOTP::respond()`` requires both ``expectedAudience`` and ``expectedContext``.
It compares them exactly with the received challenge and refuses stale/future
challenges before signing. These checks make accidental blind signing harder,
but their security depends on where the expected values come from.

**AOTP provides asymmetric proof-of-possession and replay-resistant challenge
authentication. Phishing resistance is an end-to-end property of the consuming
client and verifier.** A generic AOTP transport cannot independently determine
which website/app initiated the request or whether a live challenge was relayed
through a phishing intermediary.

A real-time relay can obtain a genuine challenge from the real verifier, forward
it to the victim, and forward the resulting valid signature back. The audience
and context in that relayed challenge can themselves be genuine. Therefore the
client must not derive its expectations by copying those fields from the
received challenge.

Required client/verifier rules for stronger resistance:

* pin or otherwise independently authenticate the verifier identity used as
  ``expectedAudience``;
* derive ``expectedContext`` from trusted local operation state, not from the
  challenge payload;
* bind context to a fresh locally known login/session/transaction identifier,
  not only a constant such as ``login``;
* when authorizing business data, canonicalize the same transaction details on
  both sides and display/verify them before signing;
* consume the corresponding application flow/transaction together with the
  successful AOTP result so a proof cannot be detached from its intended action;
* never call ``AOTP::respond(..., $challenge->audience, $challenge->context)`` as
  a shortcut;
* use short challenge TTLs and trustworthy client/verifier clocks; and
* describe the integration as proof-of-possession/replay-resistant unless the
  surrounding client/verifier protocol has been independently reviewed for
  phishing/relay resistance.

When browser-origin-bound phishing resistance is the requirement, prefer
Passkey/WebAuthn. Browsers/authenticators participate in enforcing RP-ID/origin
relationships that a generic AOTP library cannot reproduce solely from a signed
challenge.

GridOTP observation model
-------------------------

GridOTP changes both requested positions and the balanced symbol-to-digit map on
every challenge. One captured response cannot authenticate a later challenge and
does not directly reveal the enrolled secret. However, an observer who repeatedly
captures full grids, positions, and responses can intersect candidate sets and
recover secret symbols over time. Treat GridOTP as one knowledge factor. It is
not shoulder-surfing proof and is not a replacement for standards-based passkeys
where those are usable.

Passkeys
--------

``Passkey`` intentionally delegates WebAuthn parsing, attestation, assertion
signature verification, RP-ID/origin checks, user-verification checks, and
counter validation to ``web-auth/webauthn-lib``. Do not replace those validators
with custom COSE/CBOR/signature parsing.

Registration requests resident/discoverable credentials, requires user
verification, and defaults attestation conveyance to ``none``. Applications
remain responsible for authenticated enrollment policy, duplicate-credential
policy, credential naming/revocation, device management, and recovery.

For discoverable/usernameless authentication, resolve the durable
``CredentialRecord`` using ``extractCredentialId()`` and then pass that exact
record into ``finishAuthentication()``. Persist the updated record returned on
success. Reject disabled/revoked credentials before completing the login/session
transition.

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

After authentication success, rotate the session identifier, bind the
authenticated state to the intended account and flow, enforce any step-up policy
in the application, and prevent reuse of pre-authentication sessions. The package
does not perform these actions.

Audit
-----

Useful redacted events include enrollment started/completed/abandoned, factor
verified, replay rejected, passkey registered/revoked, recovery
used/regenerated, rotation activated, and factor revoked. Record factor
generation and coarse reason without secrets, codes, signatures, ceremony
payloads, credential records, provisioning payloads, or unnecessary personal
data.

Security review checklist
-------------------------

Before launch, verify:

#. secrets and HMAC keys are purpose-separated and protected;
#. AOTP private keys never reach verifier storage;
#. AOTP expected audience comes from pinned/trusted client configuration and
   expected context comes from trusted local operation state rather than received
   challenge fields;
#. AOTP contexts contain fresh flow/transaction binding and the application
   consumes that flow when authentication succeeds;
#. passkey origins/RP ID are fixed trusted configuration and CredentialRecords
   are persisted after successful assertions;
#. MobileOTP is used only where legacy compatibility is actually required;
#. all production state stores pass real concurrent race tests;
#. replay protection is enabled for authentication endpoints;
#. factor IDs change across secret/counter generations;
#. time is synchronized and acceptance windows are minimal;
#. every request path is rate-limited;
#. provisioning/ceremony responses cannot be cached or logged;
#. recovery policy is documented and tested;
#. successful authentication rotates session state;
#. exceptions fail closed without sensitive output; and
#. key/secret/credential compromise runbooks exist.
