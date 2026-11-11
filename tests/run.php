<?php

declare(strict_types=1);

/*
 * The SDK's own tests: `php tests/run.php`. No framework and no network; Naxa is played by
 * FakeNaxa, which checks what it receives the way Naxa does. The same SDK is also run against
 * the real Naxa by the platform's suite (tests/Sdk in the naxa-platform repository).
 */

namespace Naxa\Sdk\Tests;

use Naxa\Sdk\AuthorizationRequest;
use Naxa\Sdk\Cache\FileCache;
use Naxa\Sdk\Cache\MemoryCache;
use Naxa\Sdk\Exception\ApiError;
use Naxa\Sdk\Exception\AuthorizationFailed;
use Naxa\Sdk\Exception\ConfigurationError;
use Naxa\Sdk\Exception\OAuthError;
use Naxa\Sdk\Exception\SignatureError;
use Naxa\Sdk\Exception\TransportError;
use Naxa\Sdk\Http\CurlTransport;
use Naxa\Sdk\Http\Response;
use Naxa\Sdk\Internal\Jose;
use Naxa\Sdk\Key;
use Naxa\Sdk\Naxa;
use Naxa\Sdk\PublicData;
use Naxa\Sdk\TokenSet;

error_reporting(E_ALL);
// A warning or a notice anywhere in the SDK fails the test that met it ("@" still silences what it silences).
set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if ((error_reporting() & $severity) === 0) {
        return false;
    }
    throw new \ErrorException($message, 0, $severity, $file, $line);
});

require __DIR__ . '/../autoload.php';
require __DIR__ . '/FakeNaxa.php';

$assertions = 0;

function same(mixed $expected, mixed $actual, string $what = ''): void
{
    global $assertions;
    $assertions++;
    if ($expected !== $actual) {
        throw new \AssertionError(($what !== '' ? $what . ': ' : '') . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}

function yes(bool $condition, string $what): void
{
    same(true, $condition, $what);
}

/** @template T of \Throwable @param class-string<T> $class @return T */
function throws(string $class, callable $do, string $what = ''): \Throwable
{
    global $assertions;
    $assertions++;
    try {
        $do();
    } catch (\Throwable $e) {
        if ($e instanceof $class) {
            return $e;
        }
        throw new \AssertionError(($what !== '' ? $what . ': ' : '') . 'expected ' . $class . ', got ' . $e::class . ' (' . $e->getMessage() . ')');
    }
    throw new \AssertionError(($what !== '' ? $what . ': ' : '') . 'expected ' . $class . ', nothing was thrown');
}

/** An application, the Naxa it talks to, and the milliseconds it waited. */
final class World
{
    public const CLIENT = 'app_budgetbuddy';
    public const REDIRECT = 'https://budget.example/naxa/callback';

    public Key $clientKey;
    public Key $dpopKey;
    public FakeNaxa $naxa;
    public MemoryCache $cache;
    /** @var list<int> */
    public array $waited = [];

    public function __construct()
    {
        $this->clientKey = Key::generate();
        $this->dpopKey = Key::generate();
        $this->naxa = new FakeNaxa(self::CLIENT, 'main', $this->clientKey->publicKey());
        $this->cache = new MemoryCache();
    }

    public function sdk(mixed ...$over): Naxa
    {
        return new Naxa(...$over + [
            'clientId' => self::CLIENT, 'keyId' => 'main', 'clientKey' => $this->clientKey->export(), 'dpopKey' => $this->dpopKey,
            'redirectUri' => self::REDIRECT, 'issuer' => FakeNaxa::ISSUER, 'apiBase' => FakeNaxa::API,
            'transport' => $this->naxa, 'cache' => $this->cache,
            'clock' => fn (): int => $this->naxa->now,
            'sleep' => function (int $milliseconds): void {
                $this->waited[] = $milliseconds;
            },
        ]);
    }

    /** The person went to Naxa and allowed: the query they come back with. @return array<string,string> */
    public function back(AuthorizationRequest $request): array
    {
        parse_str((string) parse_url($request->url, PHP_URL_QUERY), $sent);
        return ['code' => $this->naxa->codeFor((string) $sent['request_uri']), 'state' => $request->state, 'iss' => FakeNaxa::ISSUER];
    }

    public function signedIn(Naxa $sdk, array $scopes = ['profile', 'transfers:read']): TokenSet
    {
        $request = $sdk->begin($scopes);
        return $sdk->complete($request, $this->back($request));
    }

    /** @return list<string> "METHOD path" of every request Naxa received */
    public function seen(): array
    {
        return array_map(static fn (array $r): string => $r['method'] . ' ' . parse_url($r['url'], PHP_URL_PATH), $this->naxa->requests);
    }

    /** @return array<string,mixed> the claims of a signed token, unverified */
    public static function claims(string $jwt): array
    {
        return (array) json_decode((string) Jose::decode(explode('.', $jwt)[1]), true);
    }

    /** @return array<string,mixed> */
    public static function header(string $jwt): array
    {
        return (array) json_decode((string) Jose::decode(explode('.', $jwt)[0]), true);
    }
}

$tests = [];

$tests['a key is exported, read back, and never shown'] = static function (): void {
    $key = Key::generate();
    $again = Key::fromSecret($key->export());
    same($key->publicKey(), $again->publicKey());
    same(32, strlen((string) base64_decode($key->publicKey(), true)));
    same(64, strlen($key->sign('message')));
    // RFC 7638: the thumbprint is the SHA-256 of the key's required members, in order.
    same(Jose::encode(hash('sha256', json_encode(['crv' => 'Ed25519', 'kty' => 'OKP', 'x' => $key->jwk()['x']]), true)), $key->thumbprint());
    // A 32-byte seed gives the same key each time.
    $seed = random_bytes(32);
    same(Key::fromSecret(base64_encode($seed))->publicKey(), Key::fromSecret(base64_encode($seed))->publicKey());
    foreach (['', 'not base64 !', base64_encode('too short')] as $bad) {
        throws(ConfigurationError::class, static fn () => Key::fromSecret($bad));
    }
    $shown = print_r($key, true) . var_export($key->__debugInfo(), true);
    yes(!str_contains($shown, $key->export()) && str_contains($shown, $key->publicKey()), 'a dump shows the public half only');
    throws(\LogicException::class, static fn () => serialize($key));
};

$tests['nothing leaves in clear, and what is not configured is said'] = static function (): void {
    $w = new World();
    foreach (['http://id.naxacorp.com', 'ftp://id.naxacorp.com', 'https://user@id.naxacorp.com', 'id.naxacorp.com', 'https://id.naxacorp.com?x=1'] as $bad) {
        throws(ConfigurationError::class, static fn () => $w->sdk(issuer: $bad), $bad);
        throws(ConfigurationError::class, static fn () => $w->sdk(apiBase: $bad), $bad);
    }
    foreach (['http://id.naxacorp.localhost:8090', 'http://localhost:8090', 'http://127.0.0.1:8090', 'https://id.sandbox.naxacorp.com/'] as $good) {
        $w->sdk(issuer: $good);
    }
    throws(ConfigurationError::class, static fn () => $w->sdk(clientId: ''));
    throws(ConfigurationError::class, static fn () => $w->sdk(clientKey: 'nonsense'));
    throws(ConfigurationError::class, static fn () => $w->sdk(locale: 'fr_FR; q=1'));
    throws(ConfigurationError::class, static fn () => $w->sdk(redirectUri: null)->begin());
    throws(ConfigurationError::class, static fn () => $w->sdk()->begin(['profile email']));
    throws(ConfigurationError::class, static fn () => $w->sdk()->begin(prompt: 'maybe'));
    same([], $w->naxa->requests, 'nothing was sent');
    $shown = print_r($w->sdk(), true);
    yes(!str_contains($shown, $w->clientKey->export()) && !str_contains($shown, $w->dpopKey->export()), 'a dump of the SDK shows no key');
};

$tests['a request is pushed, bound to this browser and to the application\'s key'] = static function (): void {
    $w = new World();
    $sdk = $w->sdk();
    $request = $sdk->begin(['profile', 'wallets:read'], prompt: 'consent', maxAge: 300);
    same(['GET /.well-known/openid-configuration', 'POST /oauth2/par'], $w->seen());
    parse_str((string) $w->naxa->requests[1]['body'], $form);
    same('openid profile wallets:read', $form['scope']);
    same(['code', 'S256', World::REDIRECT, World::CLIENT, 'consent', '300'], [$form['response_type'], $form['code_challenge_method'], $form['redirect_uri'], $form['client_id'], $form['prompt'], $form['max_age']]);
    same($w->dpopKey->thumbprint(), $form['dpop_jkt']);
    same(Jose::encode(hash('sha256', $request->codeVerifier, true)), $form['code_challenge']);
    same([$request->state, $request->nonce], [$form['state'], $form['nonce']]);
    yes(preg_match('/^[A-Za-z0-9._~-]{43,128}$/', $request->codeVerifier) === 1, 'a verifier as RFC 7636 writes it');
    // The application says who it is with a signed assertion, for Naxa ID alone, for a minute.
    $assertion = $form['client_assertion'];
    same(['alg' => 'EdDSA', 'typ' => 'JWT', 'kid' => 'main'], World::header($assertion));
    $claims = World::claims($assertion);
    same([World::CLIENT, World::CLIENT, FakeNaxa::ISSUER, $w->naxa->now, $w->naxa->now + 60], [$claims['iss'], $claims['sub'], $claims['aud'], $claims['iat'], $claims['exp']]);
    yes(!isset($form['client_secret']), 'no shared secret');
    // The browser carries the reference of the request and nothing else.
    same(FakeNaxa::ISSUER . '/oauth2/authorize?client_id=' . World::CLIENT . '&request_uri=' . rawurlencode('urn:ietf:params:oauth:request_uri:00000001'), $request->url);
    same($w->naxa->now + 60, $request->expiresAt);
    // Another request: nothing is reused.
    $other = $sdk->begin();
    yes($other->state !== $request->state && $other->nonce !== $request->nonce && $other->codeVerifier !== $request->codeVerifier, 'fresh values each time');
    // What the session keeps comes back as it was.
    $kept = AuthorizationRequest::fromArray(json_decode(json_encode($request->toArray()), true));
    same($request->toArray(), $kept->toArray());
    throws(ConfigurationError::class, static fn () => AuthorizationRequest::fromArray(['url' => 'x']));
    yes(!str_contains(print_r($request, true), $request->codeVerifier), 'a dump does not show the verifier');
};

$tests['the person comes back: the code is redeemed and what Naxa ID signed is verified'] = static function (): void {
    $w = new World();
    $sdk = $w->sdk();
    $request = $sdk->begin(['profile', 'transfers:read']);
    $tokens = $sdk->complete($request, $w->back($request));
    same('usr_ada', $tokens->subject());
    same(['openid', 'profile', 'transfers:read'], $tokens->scopes);
    yes($tokens->allows('profile') && !$tokens->allows('email'), 'scopes');
    same($w->naxa->now + 300, $tokens->expiresAt);
    yes($tokens->refreshToken !== null, 'a refresh token');
    same('Ada Lovelace', $tokens->claims['name']);
    // The token request carried a proof of possession for this very address, signed by the key of the proofs.
    $sent = $w->naxa->requests[count($w->naxa->requests) - 2];
    same('POST ' . FakeNaxa::ISSUER . '/oauth2/token', $sent['method'] . ' ' . $sent['url']);
    $proof = $sent['headers']['dpop'];
    same(['alg' => 'EdDSA', 'typ' => 'dpop+jwt', 'jwk' => $w->dpopKey->jwk()], World::header($proof));
    $claims = World::claims($proof);
    same(['POST', FakeNaxa::ISSUER . '/oauth2/token', $w->naxa->now], [$claims['htm'], $claims['htu'], $claims['iat']]);
    yes(!isset($claims['ath']), 'no token yet, no token hash');
    // Naxa ID's keys were asked for once, after the token.
    same('GET /oauth2/jwks', $w->seen()[count($w->seen()) - 1]);
    // Kept on the server and read back.
    $kept = TokenSet::fromArray(json_decode(json_encode($tokens->toArray()), true));
    same($tokens->toArray(), $kept->toArray());
    $shown = print_r($tokens, true);
    yes(!str_contains($shown, $tokens->accessToken) && !str_contains($shown, (string) $tokens->refreshToken), 'a dump shows no token');
    throws(ConfigurationError::class, static fn () => TokenSet::fromArray([]));
};

$tests['an answer that is not this browser\'s, not Naxa\'s, or a refusal'] = static function (): void {
    $w = new World();
    $sdk = $w->sdk();
    $request = $sdk->begin();
    $before = count($w->naxa->requests);
    $back = $w->back($request);
    foreach ([
        'state_mismatch' => ['state' => 'someone-elses'] + $back,
        'state_mismatch ' => array_diff_key($back, ['state' => 1]),
        'issuer_mismatch' => ['iss' => 'https://id.attacker.example'] + $back,
        'issuer_mismatch ' => array_diff_key($back, ['iss' => 1]),
        'code_missing' => array_diff_key($back, ['code' => 1]),
        'access_denied' => ['error' => 'access_denied'] + array_diff_key($back, ['code' => 1]),
        'login_required' => ['error' => 'login_required'] + $back,
        'error' => ['error' => "<script>alert(1)</script>"] + $back,
    ] as $reason => $query) {
        $e = throws(AuthorizationFailed::class, static fn () => $sdk->complete($request, $query), $reason);
        same(trim($reason), $e->reason);
        same(trim($reason) === 'access_denied', $e->refusedByThePerson());
    }
    // The return address opened by hand, or a second time: the session holds no request, or not one of the SDK's.
    foreach ([null, [], ['url' => 'https://id.naxa.test/oauth2/authorize'], ['state' => $request->state]] as $kept) {
        $e = throws(AuthorizationFailed::class, static fn () => $sdk->complete($kept, $back));
        same(['request_missing', false], [$e->reason, $e->refusedByThePerson()]);
    }
    same($before, count($w->naxa->requests), 'none of these reached Naxa');
    // What toArray() gave, as a session keeps it, is as good as the request itself.
    $again = $sdk->begin();
    same('usr_ada', $sdk->complete($again->toArray(), $w->back($again))->subject());
    // Someone else's code with this browser's state: PKCE fails at Naxa.
    $other = $sdk->begin();
    $e = throws(OAuthError::class, static fn () => $sdk->complete($request, ['code' => $w->back($other)['code']] + $back));
    same(['invalid_grant', 'pkce_failed', 400, true], [$e->error, $e->description, $e->status, $e->needsNewAuthorization()]);
};

$tests['an ID token is believed only when Naxa ID signed it for this application and this request'] = static function (): void {
    $attempt = static function (callable $bend): AuthorizationFailed {
        $w = new World();
        $sdk = $w->sdk();
        $request = $sdk->begin();
        $bend($w);
        return throws(AuthorizationFailed::class, static fn () => $sdk->complete($request, $w->back($request)));
    };
    foreach ([
        'another key' => static fn (World $w) => $w->naxa->idTokenSignedWith = Key::generate(),
        'another issuer' => static fn (World $w) => $w->naxa->idTokenClaims = ['iss' => 'https://id.attacker.example'],
        'another application' => static fn (World $w) => $w->naxa->idTokenClaims = ['aud' => 'app_other', 'azp' => 'app_other'],
        'several audiences, authorized party another' => static fn (World $w) => $w->naxa->idTokenClaims = ['aud' => [World::CLIENT, 'app_other'], 'azp' => 'app_other'],
        'another request' => static fn (World $w) => $w->naxa->idTokenClaims = ['nonce' => 'replayed'],
        'no nonce' => static fn (World $w) => $w->naxa->idTokenClaims = ['nonce' => null],
        'expired' => static fn (World $w) => $w->naxa->idTokenClaims = ['exp' => $w->naxa->now - 120],
        'from the future' => static fn (World $w) => $w->naxa->idTokenClaims = ['iat' => $w->naxa->now + 600],
        'no one' => static fn (World $w) => $w->naxa->idTokenClaims = ['sub' => null],
    ] as $what => $bend) {
        same('id_token_invalid', $attempt($bend)->reason, $what);
    }
    // Naxa ID changed its key since its keys were kept: they are asked for once more, and that is all.
    $w = new World();
    $sdk = $w->sdk();
    $w->signedIn($sdk);
    $w->naxa->idKey = Key::generate();
    $w->naxa->idKeyId = 'id-2027';
    $w->naxa->requests = [];
    same('usr_ada', $w->signedIn($sdk)->subject());
    same(1, count(array_keys($w->seen(), 'GET /oauth2/jwks', true)), 'one more reading of the keys');
    // A token that is not bound to the application's key is not accepted.
    $w = new World();
    $w->naxa->tokenType = 'Bearer';
    throws(TransportError::class, static fn () => $w->signedIn($w->sdk()));
};

$tests['a server that is not the issuer it is asked for'] = static function (): void {
    $w = new World();
    $w->naxa->instead['GET /.well-known/openid-configuration'] = [FakeNaxa::json(200, ['issuer' => 'https://id.attacker.example'] + $w->naxa->discovery())];
    throws(TransportError::class, static fn () => $w->sdk()->begin());
    $w = new World();
    $w->naxa->instead['GET /.well-known/openid-configuration'] = [FakeNaxa::json(200, ['token_endpoint' => 'http://id.naxa.test/oauth2/token'] + $w->naxa->discovery())];
    throws(ConfigurationError::class, static fn () => $w->sdk()->begin(), 'an endpoint in clear is refused');
    // What Naxa ID publishes is asked for once and kept.
    $w = new World();
    $sdk = $w->sdk();
    $w->signedIn($sdk);
    $w->signedIn($sdk);
    same(1, count(array_keys($w->seen(), 'GET /.well-known/openid-configuration', true)));
    same(1, count(array_keys($w->seen(), 'GET /oauth2/jwks', true)));
};

$tests['the API: who is asking, with which proof, and what a refusal says'] = static function (): void {
    $w = new World();
    $sdk = $w->sdk(locale: 'fr');
    $tokens = $w->signedIn($sdk);
    $w->naxa->requests = [];
    $me = $sdk->person($tokens)->me();
    same(['usr_ada', 'Ada Lovelace'], [$me['id'], $me['name']]);
    $sent = $w->naxa->requests[0];
    same('DPoP ' . $tokens->accessToken, $sent['headers']['authorization']);
    same(['2026-11-10', 'fr', 'application/json', 'naxa-php/' . Naxa::VERSION], [$sent['headers']['naxa-version'], $sent['headers']['accept-language'], $sent['headers']['accept'], $sent['headers']['user-agent']]);
    $claims = World::claims($sent['headers']['dpop']);
    same(['GET', FakeNaxa::API . '/v1/me', Jose::encode(hash('sha256', $tokens->accessToken, true))], [$claims['htm'], $claims['htu'], $claims['ath']]);
    // A refusal, as the API words it.
    $w->naxa->instead['GET /v1/me'] = [FakeNaxa::json(403, ['error' => ['type' => 'permission_error', 'code' => 'insufficient_scope', 'message' => 'Cette application n\'a pas demandé « profile ».', 'param' => 'scope', 'request_id' => 'req_42']])];
    $e = throws(ApiError::class, static fn () => $sdk->person($tokens)->me());
    same([403, 'permission_error', 'insufficient_scope', 'scope', 'req_42', null, false], [$e->status, $e->type, $e->errorCode, $e->param, $e->requestId, $e->retryAfter, $e->needsNewAuthorization()]);
    yes(str_contains($e->getMessage(), 'profile'), 'the message is the API\'s');
    // An answer that is not the API's is not read as one.
    $w->naxa->instead['GET /v1/me'] = [new Response(502, ['content-type' => 'text/html'], '<html>Bad gateway</html>')];
    throws(TransportError::class, static fn () => $sdk->person($tokens)->me());
    $w->naxa->instead['GET /v1/me'] = [FakeNaxa::json(500, ['message' => 'oops'])];
    throws(TransportError::class, static fn () => $sdk->person($tokens)->me());
    // The address of a proof never carries the query.
    $w->naxa->requests = [];
    $sdk->person($tokens)->transfers(limit: 3);
    same(FakeNaxa::API . '/v1/transfers?limit=3', $w->naxa->requests[0]['url']);
    same(FakeNaxa::API . '/v1/transfers', World::claims($w->naxa->requests[0]['headers']['dpop'])['htu']);
};

$tests['a list is read page after page'] = static function (): void {
    $w = new World();
    $sdk = $w->sdk();
    $person = $sdk->person($w->signedIn($sdk));
    $page = $person->transfers(limit: 3);
    same(['ctx_7', 'ctx_6', 'ctx_5'], array_column($page->data, 'id'));
    same([3, true], [count($page), $page->hasMore]);
    same(['ctx_7', 'ctx_6', 'ctx_5'], array_column(iterator_to_array($page), 'id'));
    $next = $page->next();
    same(['ctx_4', 'ctx_3', 'ctx_2'], array_column($next->data, 'id'));
    $last = $next->next();
    same([['ctx_1'], false, null], [array_column($last->data, 'id'), $last->hasMore, $last->next()]);
    same(['ctx_7', 'ctx_6', 'ctx_5', 'ctx_4', 'ctx_3', 'ctx_2', 'ctx_1'], array_column(iterator_to_array($page->all(), false), 'id'));
    // The loop asks for a page only when it reaches it.
    $w->naxa->requests = [];
    foreach ($person->transfers(limit: 2)->all() as $transfer) {
        if ($transfer['id'] === 'ctx_6') {
            break;
        }
    }
    same(1, count($w->naxa->requests));
};

$tests['the access token is renewed by itself, and the application keeps the new one'] = static function (): void {
    $w = new World();
    $sdk = $w->sdk();
    $tokens = $w->signedIn($sdk);
    $kept = [];
    $person = $sdk->person($tokens, function (TokenSet $new) use (&$kept): void {
        $kept[] = $new;
    });
    $person->me();
    same([], $kept, 'nothing to renew yet');
    // Five minutes later the access token has expired.
    $w->naxa->now += 300;
    $w->naxa->requests = [];
    $person->me();
    same(['POST /oauth2/token', 'GET /v1/me'], $w->seen());
    same(1, count($kept));
    yes($kept[0]->accessToken !== $tokens->accessToken, 'a new access token');
    same([$tokens->refreshToken, $tokens->claims, $w->naxa->now + 300], [$kept[0]->refreshToken, $kept[0]->claims, $kept[0]->expiresAt]);
    same($kept[0], $person->tokens());
    // The token ended earlier than it said: one renewal, one more try.
    unset($w->naxa->accessTokens[$kept[0]->accessToken]);
    $w->naxa->requests = [];
    same('usr_ada', $person->me()['id']);
    same(['GET /v1/me', 'POST /oauth2/token', 'GET /v1/me'], $w->seen());
    same(2, count($kept));
    same($tokens->refreshToken, $kept[1]->refreshToken, 'the refresh token stays the same as long as Naxa ID gives no other');
    // Naxa ID replaces the refresh token with a renewal: the application is handed the new
    // one, the next renewal uses it, and the old one is not sent again.
    $w->naxa->rotates = true;
    $w->naxa->now += 300;
    $person->me();
    same(3, count($kept));
    yes($kept[2]->refreshToken !== null && $kept[2]->refreshToken !== $tokens->refreshToken, 'a new refresh token');
    same([$kept[2]->refreshToken], array_keys($w->naxa->refreshTokens));
    $w->naxa->now += 300;
    $w->naxa->requests = [];
    $person->me();
    parse_str((string) $w->naxa->requests[0]['body'], $renewal);
    same($kept[2]->refreshToken, $renewal['refresh_token']);
    same([4, $kept[3]->refreshToken], [count($kept), array_keys($w->naxa->refreshTokens)[0]]);
    $w->naxa->rotates = false;
    // The person withdrew their consent: the renewal says so, and nothing loops.
    $w->naxa->refreshTokens = [];
    $w->naxa->now += 300;
    $w->naxa->requests = [];
    $e = throws(OAuthError::class, static fn () => $person->me());
    same(['invalid_grant', true], [$e->error, $e->needsNewAuthorization()]);
    same(['POST /oauth2/token'], $w->seen());
    // Tokens without a refresh token are used as they are.
    $bare = new TokenSet('access-unknown', $w->naxa->now - 10, ['openid']);
    $e = throws(ApiError::class, static fn () => $sdk->person($bare)->me());
    same(['invalid_token', true], [$e->errorCode, $e->needsNewAuthorization()]);
    throws(ConfigurationError::class, static fn () => $sdk->refresh($bare));
};

$tests['what the application holds for a person is ended'] = static function (): void {
    $w = new World();
    $sdk = $w->sdk();
    $tokens = $w->signedIn($sdk);
    $sdk->revoke($tokens);
    same([], $w->naxa->refreshTokens);
    parse_str((string) $w->naxa->requests[count($w->naxa->requests) - 1]['body'], $form);
    same($tokens->refreshToken, $form['token']);
    yes(isset($form['client_assertion']), 'the application says who it is');
};

$tests['a request is sent again only when it may be'] = static function (): void {
    $w = new World();
    $sdk = $w->sdk();
    $tokens = $w->signedIn($sdk);
    $person = $sdk->person($tokens);
    // No answer twice, then an answer: a read is sent again, each time with a new proof.
    $w->naxa->requests = [];
    $w->naxa->silent = 2;
    same('usr_ada', $person->me()['id']);
    same(3, count($w->naxa->requests));
    same(3, count(array_unique(array_map(static fn (array $r): string => World::claims($r['headers']['dpop'])['jti'], $w->naxa->requests))), 'a proof is used once');
    same([200, 400], $w->waited);
    // Never more than asked.
    $w->naxa->silent = 3;
    throws(TransportError::class, static fn () => $person->me());
    $w->naxa->silent = 0;
    $w->waited = [];
    $none = $w->sdk(maxRetries: 0);
    $w->naxa->silent = 1;
    throws(TransportError::class, static fn () => $none->person($tokens)->me());
    same([], $w->waited);
    // Naxa asks to come back in a second: the SDK does.
    $busy = static fn (int $status, string $code, array $headers): Response => FakeNaxa::json($status, ['error' => ['type' => $status === 429 ? 'rate_limit_error' : 'api_error', 'code' => $code, 'message' => 'Later.', 'request_id' => 'req_1']], $headers);
    $w->naxa->instead['GET /v1/me'] = [$busy(429, 'rate_limited', ['retry-after' => '1']), $busy(503, 'temporarily_unavailable', [])];
    same('usr_ada', $person->me()['id']);
    same([1000, 1000], $w->waited);
    // In two minutes: that is for the application to decide.
    $w->waited = [];
    $w->naxa->instead['GET /v1/me'] = [$busy(429, 'quota_exceeded', ['retry-after' => '120'])];
    $e = throws(ApiError::class, static fn () => $person->me());
    same([429, 'rate_limit_error', 'quota_exceeded', 120], [$e->status, $e->type, $e->errorCode, $e->retryAfter]);
    same([], $w->waited);
    // Naxa ID asks the same when it cannot answer for a moment (its database restarts): the
    // SDK waits and the renewal goes through.
    $later = static fn (): Response => FakeNaxa::json(503, ['error' => 'temporarily_unavailable'], ['retry-after' => '2']);
    $w->naxa->instead['POST /oauth2/token'] = [$later()];
    $w->naxa->requests = [];
    $renewed = $sdk->refresh($tokens);
    yes($renewed->accessToken !== $tokens->accessToken, 'a new access token');
    same([['POST /oauth2/token', 'POST /oauth2/token'], [2000]], [$w->seen(), $w->waited]);
    // A wait that outlasts the attempts is not a refusal: Naxa is not there, the tokens are worth what they were.
    $w->waited = [];
    $w->naxa->instead['POST /oauth2/token'] = [$later(), $later(), $later()];
    $e = throws(TransportError::class, static fn () => $sdk->refresh($tokens));
    yes(str_contains($e->getMessage(), '503'), $e->getMessage());
    same([2000, 2000], $w->waited);
    same($renewed->refreshToken, $sdk->refresh($tokens)->refreshToken, 'and the next time it works');
    // Asked too often, Naxa ID says so in the same way: a wait, then a renewal, and never a refusal.
    $often = static fn (): Response => FakeNaxa::json(429, ['error' => 'rate_limited'], ['retry-after' => '3']);
    $w->waited = [];
    $w->naxa->instead['POST /oauth2/token'] = [$often()];
    same($renewed->refreshToken, $sdk->refresh($tokens)->refreshToken);
    same([3000], $w->waited);
    $w->naxa->instead['POST /oauth2/token'] = [$often(), $often(), $often()];
    $e = throws(TransportError::class, static fn () => $sdk->refresh($tokens));
    yes(str_contains($e->getMessage(), '429'), $e->getMessage());
    // Ending an authorization is not done when Naxa did not hear it.
    $w->naxa->instead['POST /oauth2/revoke'] = [$later(), $later(), $later()];
    throws(TransportError::class, static fn () => $sdk->revoke($tokens));
    yes($w->naxa->refreshTokens !== [], 'still in force at Naxa');
    $w->waited = [];
    // A code is redeemed once: no answer is no answer.
    $request = $sdk->begin();
    $w->naxa->requests = [];
    $w->naxa->silent = 1;
    throws(TransportError::class, static fn () => $sdk->complete($request, $w->back($request)));
    same(1, count($w->naxa->requests));
    // A write is sent again with the same idempotency key, so that it is done once.
    $w->naxa->requests = [];
    $w->naxa->silent = 0;
    $app = $sdk->application();
    $app->webhookEndpoints();
    $w->naxa->requests = [];
    $w->naxa->silent = 1;
    $endpoint = $app->createWebhookEndpoint('https://budget.example/naxa/events', ['transfer.*']);
    same(['we_1', 'https://budget.example/naxa/events', ['transfer.*']], [$endpoint['id'], $endpoint['url'], $endpoint['event_types']]);
    same(2, count($w->naxa->requests));
    yes(strlen($w->naxa->requests[0]['headers']['idempotency-key']) >= 16, 'a key chosen by the SDK');
    same($w->naxa->requests[0]['headers']['idempotency-key'], $w->naxa->requests[1]['headers']['idempotency-key']);
    same(['application/json', '{"url":"https://budget.example/naxa/events","event_types":["transfer.*"]}'], [$w->naxa->requests[1]['headers']['content-type'], $w->naxa->requests[1]['body']]);
    $app->createWebhookEndpoint('https://budget.example/naxa/events', ['transfer.*'], 'my-own-key-0001');
    same('my-own-key-0001', $w->naxa->requests[2]['headers']['idempotency-key']);
};

$tests['a server that asks proofs to carry its nonce is given it'] = static function (): void {
    $w = new World();
    $sdk = $w->sdk();
    $nonces = static fn (World $w, string $path): array => array_values(array_map(
        static fn (array $r): ?string => World::claims($r['headers']['dpop'])['nonce'] ?? null,
        array_filter($w->naxa->requests, static fn (array $r): bool => parse_url($r['url'], PHP_URL_PATH) === $path),
    ));
    // Naxa ID asks for its nonce when the code is redeemed: the same request leaves once more
    // with it, although redeeming a code is not something that is sent again.
    $w->naxa->idNonce = 'id-nonce-1';
    $request = $sdk->begin(['profile', 'transfers:read']);
    $w->naxa->requests = [];
    $tokens = $sdk->complete($request, $w->back($request));
    same([null, 'id-nonce-1'], $nonces($w, '/oauth2/token'));
    $sent = array_values(array_filter($w->naxa->requests, static fn (array $r): bool => str_ends_with($r['url'], '/oauth2/token')));
    parse_str((string) $sent[0]['body'], $first);
    parse_str((string) $sent[1]['body'], $second);
    yes($first['client_assertion'] !== $second['client_assertion'], 'an assertion is used once');
    yes(World::claims($sent[0]['headers']['dpop'])['jti'] !== World::claims($sent[1]['headers']['dpop'])['jti'], 'a proof is used once');
    same($first['code'], $second['code']);
    same([], $w->waited, 'it is not a wait');
    // From then on its proofs carry it at once.
    $w->naxa->requests = [];
    $tokens = $sdk->refresh($tokens);
    same(['id-nonce-1'], $nonces($w, '/oauth2/token'));
    // The API has a nonce of its own: Naxa ID's is not sent to it.
    $w->naxa->apiNonce = 'api-nonce-1';
    $w->naxa->requests = [];
    $person = $sdk->person($tokens);
    same('usr_ada', $person->me()['id']);
    same([null, 'api-nonce-1'], $nonces($w, '/v1/me'));
    same('usr_ada', $person->me()['id']);
    same([null, 'api-nonce-1', 'api-nonce-1'], $nonces($w, '/v1/me'));
    // It changes its nonce with an answer: the next proof carries the new one, with no refusal in between.
    $w->naxa->apiNonceNext = 'api-nonce-2';
    $person->me();
    $w->naxa->requests = [];
    $person->me();
    same(['api-nonce-2'], $nonces($w, '/v1/me'));
    // Another process with the same cache starts with what this one learnt, for each of the two.
    $w->naxa->requests = [];
    $other = $w->sdk();
    $other->person($tokens)->me();
    $other->refresh($tokens);
    same([['api-nonce-2'], ['id-nonce-1']], [$nonces($w, '/v1/me'), $nonces($w, '/oauth2/token')]);
    // A nonce that changed without a word: one refusal, the same request once more.
    $w->naxa->apiNonce = 'api-nonce-3';
    $w->naxa->requests = [];
    same('usr_ada', $person->me()['id']);
    same(['api-nonce-2', 'api-nonce-3'], $nonces($w, '/v1/me'));
    // A write too, with the same idempotency key.
    $w->naxa->apiNonce = 'api-nonce-4';
    $w->naxa->requests = [];
    $sdk->application()->createWebhookEndpoint('https://budget.example/naxa/events', ['transfer.*']);
    $writes = array_values(array_filter($w->naxa->requests, static fn (array $r): bool => $r['method'] === 'POST' && str_ends_with($r['url'], '/v1/webhook_endpoints')));
    same(2, count($writes));
    same($writes[0]['headers']['idempotency-key'], $writes[1]['headers']['idempotency-key']);
    same('api-nonce-4', World::claims($writes[1]['headers']['dpop'])['nonce']);

    // A server that refuses the nonce it has just given is not asked for ever: once more, then the refusal is told.
    $asks = static fn (string $nonce): Response => FakeNaxa::json(401, ['error' => ['type' => 'authentication_error', 'code' => 'invalid_dpop_proof', 'message' => 'Refused.', 'request_id' => 'req_9']],
        ['www-authenticate' => 'DPoP error="use_dpop_nonce"', 'dpop-nonce' => $nonce]);
    $w->naxa->instead['GET /v1/me'] = [$asks('never-1'), $asks('never-2'), $asks('never-3')];
    $w->naxa->requests = [];
    $e = throws(ApiError::class, static fn () => $person->me());
    same([401, 'invalid_dpop_proof', 2], [$e->status, $e->errorCode, count($w->naxa->requests)]);
    $w->naxa->instead = [];
    $w->naxa->instead['POST /oauth2/token'] = [FakeNaxa::json(400, ['error' => 'use_dpop_nonce'], ['dpop-nonce' => 'never-4']), FakeNaxa::json(400, ['error' => 'use_dpop_nonce'], ['dpop-nonce' => 'never-5'])];
    $w->naxa->requests = [];
    $e = throws(OAuthError::class, static fn () => $sdk->refresh($tokens));
    same(['use_dpop_nonce', 2], [$e->error, count($w->naxa->requests)]);
    same([], $w->waited);

    // Another refusal that happens to give a nonce is a refusal: the nonce is kept, nothing is sent again.
    $w = new World();
    $sdk = $w->sdk();
    $tokens = $w->signedIn($sdk);
    $w->naxa->instead['GET /v1/me'] = [FakeNaxa::json(403, ['error' => ['type' => 'permission_error', 'code' => 'insufficient_scope', 'message' => 'No.', 'request_id' => 'req_1']], ['dpop-nonce' => 'kept-1'])];
    $w->naxa->requests = [];
    throws(ApiError::class, static fn () => $sdk->person($tokens)->me());
    same(1, count($w->naxa->requests));
    $sdk->person($tokens)->me();
    same([null, 'kept-1'], $nonces($w, '/v1/me'));
    // What anyone reads carries no proof: there is nothing to send again.
    $w->naxa->instead['GET /v1/status'] = [$asks('for-nobody')];
    $w->naxa->requests = [];
    throws(ApiError::class, static fn () => $sdk->publicData()->status());
    same(1, count($w->naxa->requests));

    // What is not a nonce is not carried: nothing a header or a token could be bent with.
    foreach (['two words', 'a"quote', 'back\\slash', "line\nfeed", str_repeat('n', 256), '', "caf\u{e9}"] as $bent) {
        $w = new World();
        $sdk = $w->sdk();
        $tokens = $w->signedIn($sdk);
        $w->naxa->instead['GET /v1/me'] = [$asks($bent)];
        $w->naxa->requests = [];
        throws(ApiError::class, static fn () => $sdk->person($tokens)->me(), json_encode($bent, JSON_INVALID_UTF8_SUBSTITUTE));
        $sdk->person($tokens)->me();
        same([null, null], $nonces($w, '/v1/me'), json_encode($bent, JSON_INVALID_UTF8_SUBSTITUTE));
    }
};

$tests['the application\'s own token is obtained once and kept'] = static function (): void {
    $w = new World();
    $sdk = $w->sdk();
    $app = $sdk->application();
    $app->webhookEndpoints();
    $app->webhookEndpoints();
    same(['GET /.well-known/openid-configuration', 'POST /oauth2/token', 'GET /v1/webhook_endpoints', 'GET /v1/webhook_endpoints'], $w->seen());
    parse_str((string) $w->naxa->requests[1]['body'], $form);
    same('client_credentials', $form['grant_type']);
    yes(isset($w->naxa->requests[1]['headers']['dpop']), 'its token is bound to its key too');
    // Another process with the same cache does not ask again.
    $w->naxa->requests = [];
    $w->sdk()->application()->webhookEndpoints();
    same(['GET /v1/webhook_endpoints'], $w->seen());
    // The kept token no longer exists at Naxa: a new one, one more try.
    $w->naxa->accessTokens = [];
    $w->naxa->requests = [];
    $app->webhookEndpoints();
    same(['GET /v1/webhook_endpoints', 'POST /oauth2/token', 'GET /v1/webhook_endpoints'], $w->seen());
    // Close to its end, it is renewed before it is used.
    $w->naxa->now += 280;
    $w->naxa->requests = [];
    $app->webhookEndpoints();
    same(['POST /oauth2/token', 'GET /v1/webhook_endpoints'], $w->seen());
    // An application Naxa does not know.
    $stranger = new World();
    $stranger->naxa = $w->naxa;
    $e = throws(OAuthError::class, static fn () => $stranger->sdk()->application()->webhookEndpoints());
    same(['invalid_client', 'assertion_signature', 401, false], [$e->error, $e->description, $e->status, $e->needsNewAuthorization()]);
};

$tests['an event is believed only when Naxa signed it, recently'] = static function (): void {
    $w = new World();
    $hooks = $w->sdk()->webhooks();
    $event = ['id' => 'evt_000000000000000000000001', 'object' => 'event', 'type' => 'transfer.completed', 'created' => $w->naxa->now, 'data' => ['object' => ['amount' => 1250]]];
    [$body, $signature] = $w->naxa->delivery($event);
    same($event, $hooks->verify($body, $signature));
    same(['GET /v1/keys'], $w->seen());
    same($event, $hooks->verify($body, $signature), 'Naxa delivers at least once: the same event verifies again');
    same(1, count($w->naxa->requests), 'the keys are kept');
    $refused = static fn (string $body, string $signature, int $tolerance = 300): string => throws(SignatureError::class, static fn () => $hooks->verify($body, $signature, $tolerance))->reason;
    same('signature_invalid', $refused(str_replace('1250', '9950', $body), $signature), 'a body that changed');
    same('signature_invalid', $refused($body . ' ', $signature), 'byte for byte');
    same('signature_invalid', $refused(...$w->naxa->delivery($event, key: Key::generate())), 'another key under Naxa\'s name');
    foreach (['', 'ed25519=abc', 't=1,kid=x', str_replace('t=', 't=-', $signature), $signature . ',extra=1', "t=1,kid=a\n,ed25519=" . str_repeat('A', 86)] as $bad) {
        same('header_malformed', $refused($body, $bad), $bad);
    }
    same('too_old', $refused(...$w->naxa->delivery($event, at: $w->naxa->now - 301)));
    same('too_old', $refused(...$w->naxa->delivery($event, at: $w->naxa->now + 301)), 'nor from the future');
    [$late, $lateSignature] = $w->naxa->delivery($event, at: $w->naxa->now - 200);
    same($event, $hooks->verify($late, $lateSignature));
    same('too_old', $refused($late, $lateSignature, 60), 'the application may be stricter');
    // A key Naxa uses for something else signs no event.
    $w->naxa->requests = [];
    same('key_unknown', $refused(...$w->naxa->delivery($event, keyId: 'pol-2026')));
    same(1, count($w->naxa->requests), 'the keys were asked for once more, no more');
    // Naxa changed its key: the list is read again and the event verifies.
    $w->naxa->eventKey = Key::generate();
    $w->naxa->eventKeyId = 'evt-2027';
    same($event, $hooks->verify(...$w->naxa->delivery($event)));
    // Signed, but not an event.
    same('payload_invalid', $refused(...$w->naxa->delivery(['hello' => 'world'])));
};

$tests['what anyone reads needs no application'] = static function (): void {
    $w = new World();
    $open = PublicData::of(FakeNaxa::API, $w->naxa);
    same(['operational', false], [$open->status()['status'], $open->status()['livemode']]);
    same(['monetary_policy', 'events'], array_column($open->keys()->data, 'use'));
    yes(!isset($w->naxa->requests[0]['headers']['authorization']) && !isset($w->naxa->requests[0]['headers']['dpop']), 'no token, no proof');
    same('operational', $w->sdk()->publicData()->status()['status']);
    throws(ConfigurationError::class, static fn () => PublicData::of('http://api.naxacorp.com'));
};

$tests['the file cache keeps what it is given, for as long as asked'] = static function (): void {
    $directory = sys_get_temp_dir() . '/naxa-sdk-test-' . bin2hex(random_bytes(6));
    try {
        $cache = new FileCache($directory . '/nested');
        same(null, $cache->get('a'));
        $cache->set('a', "one\ntwo", 60);
        same("one\ntwo", $cache->get('a'));
        same("one\ntwo", (new FileCache($directory . '/nested'))->get('a'), 'another process reads it');
        $files = glob($directory . '/nested/*.cache') ?: [];
        same(1, count($files));
        same('0600', substr(sprintf('%o', fileperms($files[0])), -4));
        $cache->set('b', 'gone', -1);
        same(null, $cache->get('b'), 'expired');
        $cache->delete('a');
        same(null, $cache->get('a'));
        // With it, the application's token outlives the request that obtained it.
        $w = new World();
        $w->cache = new MemoryCache();
        $w->sdk(cache: $cache)->application()->webhookEndpoints();
        $w->naxa->requests = [];
        $w->sdk(cache: new FileCache($directory . '/nested'))->application()->webhookEndpoints();
        same(['GET /v1/webhook_endpoints'], $w->seen());
    } finally {
        foreach (glob($directory . '/nested/*') ?: [] as $file) {
            unlink($file);
        }
        @rmdir($directory . '/nested');
        @rmdir($directory);
    }
};

$tests['the curl transport sends what it is given, follows nothing and gives up in time'] = static function (): void {
    // A real HTTP server on this machine, on a port that is free.
    $probe = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) substr(strrchr((string) stream_socket_get_name($probe, false), ':'), 1);
    fclose($probe);
    $null = ['file', '/dev/null', 'w'];
    $server = proc_open([PHP_BINARY, '-S', '127.0.0.1:' . $port, __DIR__ . '/server.php'], [['file', '/dev/null', 'r'], $null, $null], $pipes);
    yes(is_resource($server), 'the test server starts');
    putenv('NO_PROXY=127.0.0.1,localhost');
    putenv('no_proxy=127.0.0.1,localhost');
    $base = 'http://127.0.0.1:' . $port;
    try {
        for ($i = 0; $i < 50 && !($up = @fsockopen('127.0.0.1', $port, $errno, $error, 0.2)); $i++) {
            usleep(100_000);
        }
        yes(isset($up) && is_resource($up), 'the test server listens');
        fclose($up);
        $curl = new CurlTransport(timeout: 2, connectTimeout: 2);
        $r = $curl->send('GET', $base . '/echo?limit=3&x=a%20b', ['Naxa-Version' => '2026-11-10', 'Accept' => 'application/json']);
        $got = $r->json();
        same([200, 'application/json', 'req_local'], [$r->status, $r->header('Content-Type'), $r->header('x-request-id')]);
        same(['GET', '/echo?limit=3&x=a%20b', '2026-11-10', ''], [$got['method'], $got['uri'], $got['headers']['naxa-version'], $got['body']]);
        yes(!isset($got['headers']['expect']), 'no Expect header');
        $r = $curl->send('POST', $base . '/created', ['Content-Type' => 'application/json', 'Idempotency-Key' => 'k-1'], '{"a":"é"}');
        $got = $r->json();
        same([201, 'POST', '{"a":"é"}', 'application/json', 'k-1'], [$r->status, $got['method'], $got['body'], $got['headers']['content-type'], $got['headers']['idempotency-key']]);
        same('DELETE', $curl->send('DELETE', $base . '/echo')->json()['method']);
        // A redirection is an answer, not an order.
        $r = $curl->send('GET', $base . '/redirect');
        same([302, '/echo'], [$r->status, $r->header('location')]);
        // More than Naxa ever sends is not read to its end; too late is too late.
        throws(TransportError::class, static fn () => $curl->send('GET', $base . '/big'));
        $started = microtime(true);
        throws(TransportError::class, static fn () => $curl->send('GET', $base . '/slow'));
        yes(microtime(true) - $started < 2.9, 'gave up at its timeout');
        // Nothing but HTTP, and no line of its own slipped into the headers.
        throws(TransportError::class, static fn () => $curl->send('GET', 'file:///etc/hostname'));
        throws(TransportError::class, static fn () => $curl->send('GET', $base . '/echo', ['X-One' => "a\r\nX-Two: b"]));
    } finally {
        proc_terminate($server);
        proc_close($server);
    }
    // Nobody there.
    $e = throws(TransportError::class, static fn () => (new CurlTransport(2, 1))->send('GET', $base . '/echo'));
    yes(str_contains($e->getMessage(), '127.0.0.1'), 'the message names the host');
};

$failed = 0;
$only = $argv[1] ?? null;
foreach ($tests as $name => $test) {
    if ($only !== null && !str_contains($name, $only)) {
        continue;
    }
    try {
        $test();
        echo "  \u{2714} {$name}\n";
    } catch (\Throwable $e) {
        $failed++;
        echo "  \u{2718} {$name}\n      " . $e::class . ': ' . $e->getMessage() . "\n      " . basename($e->getFile()) . ':' . $e->getLine() . "\n";
        foreach (array_slice($e->getTrace(), 0, 4) as $frame) {
            echo '      at ' . basename((string) ($frame['file'] ?? '?')) . ':' . ($frame['line'] ?? '?') . "\n";
        }
    }
}
echo "\nPHP " . PHP_VERSION . ' — tests: ' . count($tests) . ', failed: ' . $failed . ', assertions: ' . $assertions . "\n";
exit($failed === 0 ? 0 : 1);
