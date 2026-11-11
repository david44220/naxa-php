# Changelog

## Unreleased

- Published under the MIT licence (`LICENSE`), in its own public repository.

## 0.1.0

The first version, written for the API version `2026-11-10`.

- Signing a person in: `Naxa::begin()`, `Naxa::complete()` (pushed authorization request, PKCE,
  state, nonce, the issuer of the answer, the ID token verified). `complete()` takes what the
  session kept as it is: when nothing is pending (the return address opened by hand, or twice),
  it refuses with `AuthorizationFailed` (`request_missing`) like any other answer not to trust.
- Tokens bound to the application's key (DPoP), renewed by themselves: `Naxa::person()`,
  `Naxa::refresh()`, `Naxa::revoke()`.
- The API: `PersonApi` (profile, wallets, balances, transfers), `ApplicationApi` (webhook
  endpoints, events), `PublicData` (supply, policies, keys, status).
- Events: `Webhooks::verify()`.
- A request Naxa asks to send later (429, 503) is sent again after `Retry-After`, as many times
  as `maxRetries` allows. A wait that outlasts them is an `ApiError` with its `retryAfter` from
  the API, and a `TransportError` from Naxa ID (429 as well as 503): not a refusal, the tokens
  the application holds are worth what they were.
- What Naxa does not ask today and may ask tomorrow without a new version of the SDK: a proof
  of possession carrying a nonce chosen by the server (RFC 9449, section 8: the refused
  request is sent once more with it, the nonce is kept in the cache and replaced whenever the
  server gives another), and a refresh token replaced at a renewal (the new one is handed to
  `onRefresh` and used from then on).
- `Key`, `bin/naxa-keys`, `FileCache`, `CurlTransport`.
