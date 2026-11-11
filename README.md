# Naxa SDK for PHP

Your application's server talking to Naxa: sign a person in with their Naxa account, read what
they allowed (profile, wallets, balances, transfers), and receive Naxa's signed events.

Pure PHP 8.3 or newer, with the `sodium`, `curl` and `json` extensions. No dependency.

Everything the API asks of an application (the FAPI 2.0 security profile) is done by the SDK:

| Naxa asks | The SDK does |
|---|---|
| The authorization request is pushed, never carried by the browser (PAR) | `begin()` |
| The answer belongs to this browser and comes from Naxa (PKCE, state, nonce, issuer) | `complete()` |
| The application proves who it is with a signature, not a shared secret (`private_key_jwt`) | every call to Naxa ID |
| Tokens are bound to the application's key and useless without it (DPoP) | every call |
| A proof carries the value Naxa chose, the day Naxa asks for one (DPoP nonce) | every call, by itself |
| A refresh token Naxa replaces is the one used from then on | `person()` hands you the new tokens to keep |
| What Naxa ID signs is verified before it is believed | `complete()` |
| Events are believed because Naxa signed them, not because of who called | `webhooks()->verify()` |

## Install

With Composer: `composer require naxa/naxa-php`. Without it, copy this folder and
`require 'naxa-php/autoload.php';`.

## 1. Keys and the application's record

```sh
php bin/naxa-keys
```

prints two secret keys (`NAXA_CLIENT_KEY`, `NAXA_DPOP_KEY`) to keep among the secrets of your
server, and one public key. In the developer console, create your application, add the public
key under a name of your choice (below: `main-2026`), and write the address people come back
to (below: `https://shop.example/naxa/callback`). The console gives the application's
identifier (`app_...`).

Keys stay on your server: never in the code, a browser or a mobile application.

```php
use Naxa\Sdk\Naxa;
use Naxa\Sdk\Cache\FileCache;

$naxa = new Naxa(
    clientId: 'app_...',
    keyId: 'main-2026',
    clientKey: getenv('NAXA_CLIENT_KEY'),
    dpopKey: getenv('NAXA_DPOP_KEY'),
    redirectUri: 'https://shop.example/naxa/callback',
    cache: new FileCache('/var/cache/shop/naxa'),   // outside the web root
);
```

For a sandbox, give its two addresses: `issuer: 'https://id.…'`, `apiBase: 'https://api.…'`.
On a test ledger the API says `livemode: false` and NXA have no value.

## 2. Sign a person in

```php
// "Connect with Naxa" was clicked.
$request = $naxa->begin(['profile', 'wallets:read', 'transfers:read']);
$_SESSION['naxa_request'] = $request->toArray();
header('Location: ' . $request->url, true, 303);
exit;
```

```php
// The person is back at redirectUri.
use Naxa\Sdk\Exception\AuthorizationFailed;

$kept = $_SESSION['naxa_request'] ?? null;
unset($_SESSION['naxa_request']);
try {
    $tokens = $naxa->complete($kept, $_GET);
} catch (AuthorizationFailed $e) {
    // $e->refusedByThePerson(): they said no. Otherwise the answer was not one to trust.
    exit;
}
$_SESSION['naxa_tokens'] = $tokens->toArray();   // on the server, never in a cookie
$userId = $tokens->subject();                    // "usr_...": this person, for your application
```

`$tokens->subject()` is the same at each sign-in and differs from one application to another.
Scopes: `profile`, `email`, `wallets:read`, `transfers:read`.

## 3. Read what they allowed

```php
use Naxa\Sdk\TokenSet;

$person = $naxa->person(TokenSet::fromArray($_SESSION['naxa_tokens']), function (TokenSet $new) {
    $_SESSION['naxa_tokens'] = $new->toArray();   // the access token was renewed: keep the new one
});

$me = $person->me();                                   // ['id' => 'usr_...', 'name' => ..., 'locale' => ...]
foreach ($person->wallets() as $wallet) {
    $balance = $person->balance($wallet['id']);        // ['amount' => 125000, 'currency' => 'nxa', ...]
}
foreach ($person->transfers(limit: 20)->all() as $transfer) {
    // every transfer, the most recent first, page after page
}
```

Amounts are integers in minor units: `125000` is 1,250.00 NXA.

The access token lives five minutes and is renewed by the SDK. To keep reading while the person
is away, store `$tokens->toArray()` with their account (encrypted at rest) instead of the
session. When the person withdraws their consent in their Naxa account, the next call throws
`OAuthError` with `needsNewAuthorization()`: forget the tokens and offer to connect again.

`$naxa->revoke($tokens)` ends what you hold for a person (they disconnected Naxa in your
application).

## 4. Receive events

Tell Naxa once where to post them:

```php
$naxa->application()->createWebhookEndpoint('https://shop.example/naxa/events', ['authorization.*', 'transfer.*']);
```

Then, at that address:

```php
use Naxa\Sdk\Exception\SignatureError;
use Naxa\Sdk\Exception\TransportError;

$payload = file_get_contents('php://input');   // byte for byte
try {
    $event = $naxa->webhooks()->verify($payload, $_SERVER['HTTP_NAXA_SIGNATURE'] ?? '');
} catch (SignatureError) {
    http_response_code(400);   // not signed by Naxa, or too old
    exit;
} catch (TransportError) {
    http_response_code(503);   // Naxa's keys could not be read: Naxa will deliver again
    exit;
}
if (alreadyHandled($event['id'])) {            // Naxa delivers at least once
    http_response_code(204);
    exit;
}
match ($event['type']) {
    'authorization.granted' => ...,            // $event['data']['object']['user'], ['scopes']
    'authorization.revoked' => ...,            // forget this person's tokens
    'transfer.completed' => ...,               // the transfer, and the person it is about
};
http_response_code(204);
```

What a server missed is read back with `$naxa->application()->events(endingBefore: $lastSeenId)`.

## Errors

| Exception | Means | Useful |
|---|---|---|
| `ApiError` | The API refused | `errorCode` (`insufficient_scope`, `rate_limited`, `resource_missing`...), `status`, `param`, `requestId`, `retryAfter` |
| `OAuthError` | Naxa ID refused | `error` (`invalid_grant`, `invalid_client`...), `description`, `needsNewAuthorization()` |
| `AuthorizationFailed` | The person did not come back with a usable answer | `reason`, `refusedByThePerson()` |
| `SignatureError` | Not an event Naxa signed recently | `reason` |
| `TransportError` | No answer could be read | |
| `ConfigurationError` | The SDK was given something it cannot work with; nothing was sent | |

All extend `NaxaException`. `errorCode` and `error` never change with the language; messages are
for developers (`locale: 'fr'` asks the API for French ones).

A read, and a write sent with its idempotency key, are sent again by the SDK when no answer
came or Naxa asked to come back within three seconds (`maxRetries`, 2 by default). A code is
redeemed once and never sent twice.

## What anyone reads

```php
use Naxa\Sdk\PublicData;

$supply = PublicData::of()->supply();    // no application, no key
```

`status()`, `supply()`, `supplyEvents()`, `monetaryPolicy()`, `feePolicy()`, `keys()`.

## Tests

```sh
php tests/run.php
```

No framework, no network: Naxa is played by `tests/FakeNaxa.php`, which checks what it receives
the way Naxa does. To test your own application, give the SDK a `transport` of yours
(`Naxa\Sdk\Http\Transport`, one method).

## Licence

MIT: see [LICENSE](LICENSE). Use it, change it and ship it in your application, open or closed.
