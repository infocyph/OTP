Provisioning
============

Authenticator convenience methods emit required parameters automatically and
omit default TOTP parameters for compatibility. HOTP always includes counter.
The parser returns effective defaults (SHA-1, six digits, and a 30-second TOTP
period) plus ``additionalParameters`` for unknown extensions.

Reserved names are case-insensitive. OCRA query algorithm/digits must match the
suite. Issuers cannot contain a colon; account labels are passed separately and
cannot be preformatted. The final ``issuer:label`` value is limited to 255 UTF-8
bytes. Duplicate queries, control characters, invalid percent encoding,
conflicting issuer identity, oversized URIs, and type-conflicting parameters are
rejected.

Use ``ProvisioningUriParser::parse()`` for generic parsing. Protocol classes do
not expose a parser that can silently parse another protocol.
