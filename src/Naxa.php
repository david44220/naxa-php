<?php

declare(strict_types=1);

namespace Naxa\Sdk;

use Naxa\Sdk\Cache\Cache;
use Naxa\Sdk\Cache\MemoryCache;
use Naxa\Sdk\Exception\AuthorizationFailed;
use Naxa\Sdk\Exception\ConfigurationError;
use Naxa\Sdk\Exception\OAuthError;
use Naxa\Sdk\Exception\TransportError;
use Naxa\Sdk\Http\CurlTransport;
use Naxa\Sdk\Http\Transport;
use Naxa\Sdk\Internal\Connection;
use Naxa\Sdk\Internal\Jose;

/**
 * An application's server talking to Naxa.
 *
 *     $naxa = new Naxa(
 *         clientId: 'app_...',                      // the application's identifier, from the developer console
 *         keyId: 'main-2026',                       // the name its public key bears in the console
 *         clientKey: getenv('NAXA_CLIENT_KEY'),     // Key::export() of the key written in the console
 *         dpopKey: getenv('NAXA_DPOP_KEY'),         // Key::export() of the key the tokens are bound to
 *         redirectUri: 'https://shop.example/naxa/callback',
 *     );
 *
 *     // 1. Send the person to Naxa.
 *     $request = $naxa->begin(['profile', 'wallets:read']);
 *     $_SESSION['naxa'] = $request->toArray();
 *     header('Location: ' . $request->url, true, 303);
 *
 *     // 2. They come back to redirectUri.
 *     $tokens = $naxa->complete(AuthorizationRequest::fromArray($_SESSION['naxa']), $_GET);
 *
 *     // 3. Read what they allowed.
 *     $me = $naxa->person($tokens)->me();
 *
 * Everything FAPI 2.0 asks of an application is done here: the request is pushed (PAR), bound
 * to this browser (PKCE, state, nonce) and to the application's key (DPoP); the application
 * proves who it is with a signed assertion (private_key_jwt), never a shared secret; what Naxa
 * ID signs is verified before anything is believed.
 */
final class Naxa
{
    public const VERSION = '0.1.0';
    /** The version of the API this SDK was written for. */
    public const API_VERSION = '2026-11-10';
    public const ISSUER = 'https://id.naxacorp.com';
    public const API = 'https://api.naxacorp.com';

    private const ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    /** How far the clocks of Naxa and of the application may differ, in seconds. */
    private const LEEWAY = 60;

    private readonly Connection $connection;
    private readonly string $issuer;
    private readonly Key $clientKey;
    private readonly Key $dpopKey;

    /**
     * @param string $issuer Naxa ID; another address for a sandbox
     * @param string $apiBase the API; another address for a sandbox
     * @param ?Cache $cache where Naxa's public keys and the application's own token are kept between requests (FileCache under PHP-FPM)
     * @param ?string $locale the language of the messages of the API's refusals ("fr", "en"...)
     * @param int $maxRetries how many times a request that may be sent again is sent again (0 to 5)
     * @param (\Closure(): int)|null $clock seconds since the Unix epoch
     * @param (\Closure(int): void)|null $sleep waits that many milliseconds
     */
    public function __construct(
        private readonly string $clientId,
        private readonly string $keyId,
        #[\SensitiveParameter] Key|string $clientKey,
        #[\SensitiveParameter] Key|string $dpopKey,
        private readonly ?string $redirectUri = null,
        string $issuer = self::ISSUER,
        string $apiBase = self::API,
        ?Transport $transport = null,
        ?Cache $cache = null,
        ?string $locale = null,
        int $maxRetries = 2,
        ?\Closure $clock = null,
        ?\Closure $sleep = null,
    ) {
        if ($clientId === '' || $keyId === '') {
            throw new ConfigurationError('clientId and keyId are both required: the application\'s identifier and the name of its key in the developer console.');
        }
        $this->clientKey = is_string($clientKey) ? Key::fromSecret($clientKey) : $clientKey;
        $this->dpopKey = is_string($dpopKey) ? Key::fromSecret($dpopKey) : $dpopKey;
        $this->issuer = Connection::address($issuer, 'issuer');
        $this->connection = new Connection(
            $apiBase,
            $transport ?? new CurlTransport(),
            $cache ?? new MemoryCache(),
            $clock ?? static fn (): int => time(),
            $sleep ?? static function (int $milliseconds): void {
                usleep($milliseconds * 1000);
            },
            $locale,
            max(0, min(5, $maxRetries)),
        );
    }

    // ------------------------------------------------------------------ a person's authorization

    /**
     * Pushes a request for a person's authorization to Naxa and gives the address to send their
     * browser to. Keep the request in the person's session (toArray()) until they come back.
     *
     * @param list<string> $scopes what the application asks to read: `profile`, `email`, `wallets:read`, `transfers:read` (`openid` is always asked)
     * @param ?string $prompt `login` to have the person sign in again, `consent` to ask again what they allow, `none` to ask nothing (they come back with an error unless everything is already in place)
     * @param ?int $maxAge the person signs in again when their session at Naxa is older than this many seconds
     * @throws OAuthError|TransportError
     */
    public function begin(array $scopes = ['profile'], ?string $prompt = null, ?int $maxAge = null): AuthorizationRequest
    {
        $scopes = array_values(array_unique(['openid', ...array_values($scopes)]));
        foreach ($scopes as $scope) {
            if (!is_string($scope) || preg_match('/^[a-z][a-z0-9:._-]{0,63}$/', $scope) !== 1) {
                throw new ConfigurationError('Not a scope: ' . (is_string($scope) ? $scope : gettype($scope)));
            }
        }
        if ($prompt !== null && !in_array($prompt, ['login', 'consent', 'none'], true)) {
            throw new ConfigurationError('prompt is "login", "consent" or "none".');
        }
        $redirectUri = $this->redirectUri();
        $state = Jose::random(24);
        $nonce = Jose::random(24);
        $verifier = Jose::random(48);
        $endpoints = $this->discovery();
        $pushed = $this->oauth($endpoints['pushed_authorization_request_endpoint'], array_filter([
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => Jose::encode(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
            // The code Naxa will give is bound to the application's key from the start.
            'dpop_jkt' => $this->dpopKey->thumbprint(),
            'prompt' => $prompt,
            'max_age' => $maxAge !== null ? (string) max(0, $maxAge) : null,
        ], static fn (?string $v): bool => $v !== null), proof: false, again: true);
        if (!is_string($pushed['request_uri'] ?? null) || $pushed['request_uri'] === '') {
            throw new TransportError('Naxa ID did not answer the reference of the pushed request.');
        }
        $url = $endpoints['authorization_endpoint'] . '?' . http_build_query(['client_id' => $this->clientId, 'request_uri' => $pushed['request_uri']], '', '&', PHP_QUERY_RFC3986);
        return new AuthorizationRequest($url, $state, $nonce, $verifier, $this->connection->now() + max(1, (int) ($pushed['expires_in'] ?? 60)));
    }

    /**
     * The person is back at redirectUri: checks that the answer belongs to this browser's
     * request and comes from Naxa, redeems the code and verifies what Naxa ID signed.
     *
     * @param AuthorizationRequest|array<string,mixed>|null $request what begin() gave, or what its toArray() gave, as kept in
     *        the person's session (null when the session holds none); forget it once this was called
     * @param array<string,mixed> $query the query of the address the person came back to ($_GET)
     * @throws AuthorizationFailed when the person refused, no request of theirs is pending, or the answer is not one to trust
     * @throws OAuthError|TransportError
     */
    public function complete(AuthorizationRequest|array|null $request, array $query): TokenSet
    {
        if (!$request instanceof AuthorizationRequest) {
            // Someone opening the return address by hand, or twice, is not a mistake of the application's.
            try {
                $request = AuthorizationRequest::fromArray($request ?? []);
            } catch (ConfigurationError) {
                throw new AuthorizationFailed('request_missing', 'No authorization request is pending in this session.');
            }
        }
        $state = $query['state'] ?? null;
        if (!is_string($state) || !hash_equals($request->state, $state)) {
            throw new AuthorizationFailed('state_mismatch');
        }
        // RFC 9207: an answer that does not name Naxa as its issuer was written by someone else.
        $issuer = $query['iss'] ?? null;
        if (!is_string($issuer) || !hash_equals($this->issuer, $issuer)) {
            throw new AuthorizationFailed('issuer_mismatch');
        }
        if (isset($query['error'])) {
            $error = $query['error'];
            throw new AuthorizationFailed(is_string($error) && preg_match('/^[a-z_]{1,64}$/', $error) === 1 ? $error : 'error');
        }
        $code = $query['code'] ?? null;
        if (!is_string($code) || $code === '') {
            throw new AuthorizationFailed('code_missing');
        }
        // A code is redeemed once: this request is never sent twice.
        $answer = $this->oauth($this->discovery()['token_endpoint'], [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri(),
            'code_verifier' => $request->codeVerifier,
        ], proof: true, again: false);
        return $this->tokens($answer, $this->signedClaims($answer['id_token'] ?? null, $request->nonce), null);
    }

    /**
     * A new access token for a person who is not there: the refresh token stays the same, and
     * gives what the person still allows. Naxa::person() does this by itself when needed.
     *
     * @throws OAuthError `invalid_grant` when the person withdrew their consent or the refresh token expired: they have to sign in again
     * @throws TransportError
     */
    public function refresh(TokenSet $tokens): TokenSet
    {
        if ($tokens->refreshToken === null) {
            throw new ConfigurationError('These tokens hold no refresh token.');
        }
        $answer = $this->oauth($this->discovery()['token_endpoint'], ['grant_type' => 'refresh_token', 'refresh_token' => $tokens->refreshToken], proof: true, again: true);
        return $this->tokens($answer, $tokens->claims, $tokens->refreshToken);
    }

    /**
     * Ends what the application holds for a person (they disconnected Naxa in the application,
     * closed their account there...): the refresh token and every access token it obtained.
     *
     * @throws OAuthError|TransportError
     */
    public function revoke(TokenSet $tokens): void
    {
        $endpoint = $this->discovery()['revocation_endpoint'] ?? null;
        if (!is_string($endpoint)) {
            throw new TransportError('Naxa ID does not publish where tokens are revoked.');
        }
        $this->oauth($endpoint, ['token' => $tokens->refreshToken ?? $tokens->accessToken], proof: false, again: true);
    }

    // ------------------------------------------------------------------ the API

    /**
     * What a person allowed the application to read. The access token is renewed by itself
     * when it has expired and the tokens hold a refresh token.
     *
     * @param (callable(TokenSet): void)|null $onRefresh called with the new tokens each time they are renewed, to keep them
     */
    public function person(TokenSet $tokens, ?callable $onRefresh = null): PersonApi
    {
        return new PersonApi($this->connection, $this, $this->dpopKey, $tokens, $onRefresh !== null ? $onRefresh(...) : null);
    }

    /** The application's own resources, in no one's name: the addresses of its events, and its events. */
    public function application(): ApplicationApi
    {
        return new ApplicationApi($this->connection, $this, $this->dpopKey);
    }

    /** What anyone reads: the supply of NXA, the policies, Naxa's public keys, the state of the API. */
    public function publicData(): PublicData
    {
        return new PublicData($this->connection);
    }

    /** Verifies the events Naxa posts to the application's addresses. */
    public function webhooks(): Webhooks
    {
        return new Webhooks($this->connection);
    }

    /**
     * The token the application obtains for itself (client_credentials), kept until it expires.
     *
     * @internal
     * @throws OAuthError|TransportError
     */
    public function applicationToken(bool $fresh = false): string
    {
        $key = 'application-token:' . hash('sha256', $this->issuer . '|' . $this->clientId . '|' . $this->dpopKey->thumbprint());
        $kept = $fresh ? null : json_decode($this->connection->cache->get($key) ?? 'null', true);
        if (is_array($kept) && is_string($kept['token'] ?? null) && (int) ($kept['expires_at'] ?? 0) - 30 > $this->connection->now()) {
            return $kept['token'];
        }
        $answer = $this->oauth($this->discovery()['token_endpoint'], ['grant_type' => 'client_credentials'], proof: true, again: true);
        $tokens = $this->tokens($answer, [], null);
        $ttl = $tokens->expiresAt - $this->connection->now() - 30;
        if ($ttl > 0) {
            $this->connection->cache->set($key, json_encode(['token' => $tokens->accessToken, 'expires_at' => $tokens->expiresAt], JSON_THROW_ON_ERROR), $ttl);
        }
        return $tokens->accessToken;
    }

    // ------------------------------------------------------------------ internals

    private function redirectUri(): string
    {
        if ($this->redirectUri === null || $this->redirectUri === '') {
            throw new ConfigurationError('redirectUri is required to sign a person in: one of the return addresses of the application\'s record.');
        }
        return $this->redirectUri;
    }

    /**
     * Where Naxa ID answers, as it publishes it.
     *
     * @return array<string,mixed>
     */
    private function discovery(): array
    {
        $document = $this->connection->published($this->issuer . '/.well-known/openid-configuration', 3600);
        // A document that names another issuer describes another server.
        if (($document['issuer'] ?? null) !== $this->issuer) {
            throw new TransportError('The server at ' . $this->issuer . ' does not name itself as the issuer.');
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'pushed_authorization_request_endpoint', 'jwks_uri'] as $name) {
            if (!is_string($document[$name] ?? null)) {
                throw new TransportError('Naxa ID does not publish its ' . $name . '.');
            }
            Connection::address($document[$name], $name);
        }
        return $document;
    }

    /** Who the application is, signed with the key its record names: for Naxa ID, now, once. */
    private function assertion(): string
    {
        $now = $this->connection->now();
        return Jose::sign(['typ' => 'JWT', 'kid' => $this->keyId], [
            'iss' => $this->clientId, 'sub' => $this->clientId, 'aud' => $this->issuer,
            'iat' => $now, 'exp' => $now + 60, 'jti' => Jose::random(18),
        ], $this->clientKey);
    }

    /**
     * A form posted to Naxa ID by the application, which says who it is.
     *
     * @param array<string,string> $form
     * @return array<string|int,mixed>
     * @throws OAuthError|TransportError
     */
    private function oauth(string $endpoint, array $form, bool $proof, bool $again): array
    {
        $response = $this->connection->send('POST', $endpoint, function () use ($endpoint, $form, $proof): array {
            $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];
            if ($proof) {
                $headers['DPoP'] = $this->connection->proof($this->dpopKey, 'POST', $endpoint);
            }
            return [$headers, http_build_query($form + ['client_assertion_type' => self::ASSERTION, 'client_assertion' => $this->assertion()], '', '&', PHP_QUERY_RFC3986)];
        }, $again);
        $answer = $response->json();
        if ($response->status >= 200 && $response->status < 300 && $answer !== null) {
            return $answer;
        }
        if ($response->status === 503 || $response->status === 429) {
            // Naxa ID asks to come back later (it cannot answer for a moment, or it was asked
            // too often), and still does after the attempts allowed. It is not a refusal: what
            // the application holds is worth what it was.
            throw new TransportError('Naxa ID is not available for the moment (HTTP ' . $response->status . ') at ' . (string) parse_url($endpoint, PHP_URL_HOST) . '.');
        }
        if (is_string($answer['error'] ?? null)) {
            throw new OAuthError($answer['error'], is_string($answer['error_description'] ?? null) ? $answer['error_description'] : null, $response->status);
        }
        throw new TransportError('An answer that is not Naxa ID\'s (HTTP ' . $response->status . ') from ' . (string) parse_url($endpoint, PHP_URL_HOST) . '.');
    }

    /**
     * @param array<string|int,mixed> $answer of the token endpoint
     * @param array<string,mixed> $claims
     */
    private function tokens(array $answer, array $claims, ?string $refreshToken): TokenSet
    {
        $token = $answer['access_token'] ?? null;
        // A token that is not bound to the application's key is not what this SDK asked for.
        if (!is_string($token) || $token === '' || strtolower((string) ($answer['token_type'] ?? '')) !== 'dpop') {
            throw new TransportError('Naxa ID did not answer an access token bound to the application\'s key.');
        }
        return new TokenSet(
            $token,
            $this->connection->now() + max(0, (int) ($answer['expires_in'] ?? 0)),
            array_values(array_filter(explode(' ', is_string($answer['scope'] ?? null) ? $answer['scope'] : ''), static fn (string $s): bool => $s !== '')),
            is_string($answer['refresh_token'] ?? null) && $answer['refresh_token'] !== '' ? $answer['refresh_token'] : $refreshToken,
            $claims,
        );
    }

    /**
     * What Naxa ID signed about the person (the ID token), once verified: signed by one of the
     * keys Naxa ID publishes, written by Naxa, for this application, for this very request, now.
     *
     * @return array<string,mixed>
     */
    private function signedClaims(mixed $idToken, string $nonce): array
    {
        if (!is_string($idToken)) {
            throw new AuthorizationFailed('id_token_invalid', 'Naxa ID sent no ID token.');
        }
        $keys = $this->signingKeys(false);
        $unknown = false;
        $verified = Jose::verify($idToken, static function (string $kid) use ($keys, &$unknown): ?string {
            $unknown = !isset($keys[$kid]);
            return $keys[$kid] ?? null;
        });
        if ($verified === null && $unknown) {
            // Naxa ID changed its key since the list was kept: ask once more.
            $keys = $this->signingKeys(true);
            $verified = Jose::verify($idToken, static fn (string $kid): ?string => $keys[$kid] ?? null);
        }
        if ($verified === null) {
            throw new AuthorizationFailed('id_token_invalid', 'The ID token is not signed by a key Naxa ID publishes.');
        }
        $claims = $verified[1];
        $now = $this->connection->now();
        $audience = $claims['aud'] ?? null;
        $forUs = $audience === $this->clientId || (is_array($audience) && in_array($this->clientId, $audience, true) && ($claims['azp'] ?? null) === $this->clientId);
        if (($claims['iss'] ?? null) !== $this->issuer
            || !$forUs
            || (isset($claims['azp']) && $claims['azp'] !== $this->clientId)
            || !is_int($claims['exp'] ?? null) || $claims['exp'] <= $now - self::LEEWAY
            || !is_int($claims['iat'] ?? null) || $claims['iat'] > $now + self::LEEWAY
            || !is_string($claims['nonce'] ?? null) || !hash_equals($nonce, $claims['nonce'])
            || !is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new AuthorizationFailed('id_token_invalid', 'The ID token was not written by Naxa ID for this application and this request.');
        }
        return $claims;
    }

    /** @return array<string,string> the public keys of Naxa ID by their identifier (32 bytes each) */
    private function signingKeys(bool $fresh): array
    {
        $set = $this->connection->published((string) $this->discovery()['jwks_uri'], 300, $fresh);
        $keys = [];
        foreach ((array) ($set['keys'] ?? []) as $jwk) {
            if (!is_array($jwk) || ($jwk['kty'] ?? null) !== 'OKP' || ($jwk['crv'] ?? null) !== 'Ed25519' || !is_string($jwk['kid'] ?? null) || !is_string($jwk['x'] ?? null)
                || (isset($jwk['use']) && $jwk['use'] !== 'sig')) {
                continue;
            }
            $raw = Jose::decode($jwk['x']);
            if ($raw !== null && strlen($raw) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                $keys[$jwk['kid']] = $raw;
            }
        }
        return $keys;
    }

    /** A dump or a log names the application, never its keys. */
    public function __debugInfo(): array
    {
        return ['client_id' => $this->clientId, 'key_id' => $this->keyId, 'issuer' => $this->issuer, 'api' => $this->connection->apiBase];
    }
}
