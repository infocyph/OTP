AOTP
====

``AOTP`` is Infocyph's asymmetric one-time challenge-response primitive. It is
not an RFC-defined OTP algorithm and is not compatible with ``otpauth://``
authenticator applications.

The verifier stores an Ed25519 public key. The client holds the corresponding
private key and signs a short-lived server-issued challenge. A successful
challenge is consumed exactly once through CacheLayer.

Security properties
-------------------

The signed challenge binds a 128-bit random challenge ID, a 256-bit random
nonce, verifier audience, optional context, issuance time, and expiration time.
The CacheLayer reservation key is derived from the complete canonical challenge,
not only its ID, so modified context or timestamps cannot reuse issued state.

AOTP uses Ed25519 from PHP's ``sodium`` extension. It does not implement RSA,
ECDSA, signature truncation, or a numeric-only proof mode.

.. code-block:: php

   use Infocyph\OTP\AOTP;

   $keys = AOTP::generateKeyPair();
   $aotp = new AOTP($keys->publicKey, 'login.example.com');
   $challenge = $aotp->issue($stateCache, 'user-42:aotp:key-v1', 'login');
   $response = AOTP::respond($keys->privateKey, $challenge, 'login.example.com');
   $result = $aotp->verifyWithResult(
       $stateCache,
       'user-42:aotp:key-v1',
       $challenge,
       $response,
   );

The explicit expected-audience argument prevents callers from accidentally
signing a challenge for a different verifier. It must come from independently
trusted client configuration, not simply from the challenge itself.

AOTP uses native CacheLayer atomics when available. Backends without atomics use
the coordinated lock fallback. A second concurrent valid request is reported as
``VerificationReason::Replay``.

Do not advertise generic AOTP as phishing resistant automatically. A relay can
proxy a live challenge unless the client independently knows and enforces the
intended verifier and, when relevant, verifies the transaction context before
signing.
