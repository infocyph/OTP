Generic OTP Guide
=================

Generic OTP is useful when you want one-time codes without managing a dedicated OTP database table, while still keeping server-side verification state.

PSR-6 cache requirement
-----------------------

The generic OTP class requires a PSR-6 cache pool implementation:

.. code-block:: php

   use Infocyph\OTP\OTP;

   $otp = new OTP(
       digitCount: 6,
       validUpto: 60,
       retry: 3,
       hashAlgorithm: 'xxh128',
       cacheAdapter: $cachePool,
   );

Codes are strings
-----------------

- Generated codes are strings.
- Verification expects a string.
- Leading zeroes are preserved.

Basic flow
----------

.. code-block:: php

   $code = $otp->generate('signup:alice@example.com');
   $otp->verify('signup:alice@example.com', $code);
   $otp->delete('signup:alice@example.com');

Retry semantics
---------------

The third argument of ``verify()`` controls whether a found record should be removed immediately:

.. code-block:: php

   $otp->verify('signup:alice@example.com', $code, deleteIfFound: false);

When ``deleteIfFound`` is ``false``, the record remains until it is verified, runs out of retries, or expires.
