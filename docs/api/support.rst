Support API
===========

``ProvisioningUriBuilder`` and ``ProvisioningUriParser`` implement bounded,
strict URI construction and parsing. ``SecretUtility`` validates canonical
Base32 syntax separately from protocol strength. ``SvgQrRenderer`` produces
bounded SVG output. ``OcraSuite`` parses OCRA exactly once. ``VerificationWindow``
represents bounded past/future drift.

Algorithm validation, OTP math, label normalization, and rotation preparation
are package support details and should not be treated as authentication workflow
or persistence APIs.
