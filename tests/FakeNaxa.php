<?php

declare(strict_types=1);

namespace Naxa\Sdk\Tests;

use Naxa\Sdk\Exception\TransportError;
use Naxa\Sdk\Http\Response;
use Naxa\Sdk\Http\Transport;
use Naxa\Sdk\Internal\Jose;
use Naxa\Sdk\Key;

/**
 * Naxa as an application's server sees it, small enough to read in one go: Naxa ID (pushed
 * requests, codes, tokens bound to a key, an ID token) and the API. It checks what it receives
 * the way Naxa does (the client assertion, the proof of possession, PKCE), so that a test that
 * passes says the SDK sends what Naxa accepts.
 */
final class FakeNaxa implements Transport
{
    public const ISSUER = 'https://id.naxa.test';
    public const API = 'https://api.naxa.test';

    /** @var list<array{method:string, url:string, headers:array<string,string>, body:?string}> every request received */
    public array $requests = [];
    /** How many of the next requests get no answer at all. */
    public int $silent = 0;
    /** @var array<string, list<Response>> answers to give instead of the usual ones, per "METHOD path", first in first out */
    public array $instead = [];
    /** The value Naxa ID asks proofs of possession to carry (RFC 9449, section 8); null asks for none. */
    public ?string $idNonce = null;
    /** The same for the API, which has a value of its own. */
    public ?string $apiNonce = null;
    /** The value the API changes to: said with its next answer, expected from the request after. */
    public ?string $apiNonceNext = null;
    /** Whether a renewal replaces the refresh token (Naxa ID does not today; an application must not depend on it). */
    public bool $rotates = false;
    /** Whether the last proof refused was refused for its nonce alone. */
    private bool $nonceMissing = false;
    public Key $idKey;
    public string $idKeyId = 'id-2026';
    public Key $eventKey;
    public string $eventKeyId = 'evt-2026';
    public int $now = 1_800_000_000;
    public int $accessTokenTtl = 300;
    /** @var array<string,mixed> overrides of the ID token's claims; null removes one */
    public array $idTokenClaims = [];
    public ?Key $idTokenSignedWith = null;
    public string $tokenType = 'DPoP';
    /** @var array<string, array<string,string>> pushed requests by their reference */
    public array $pushed = [];
    /** @var array<string, array{jkt:string, scope:string, subject:?string}> access tokens alive */
    public array $accessTokens = [];
    /** @var array<string, array{scope:string}> refresh tokens alive */
    public array $refreshTokens = [];
    /** @var array<string,true> identifiers of proofs and assertions already seen */
    private array $seen = [];
    private int $serial = 0;

    public function __construct(private readonly string $clientId, private readonly string $clientKeyId, private readonly string $clientPublicKey)
    {
        $this->idKey = Key::generate();
        $this->eventKey = Key::generate();
    }

    public function send(string $method, string $url, array $headers = [], ?string $body = null): Response
    {
        $response = $this->answer($method, $url, $headers, $body);
        if ($this->apiNonceNext !== null && str_starts_with($url, self::API . '/')) {
            $this->apiNonce = $this->apiNonceNext;
            $this->apiNonceNext = null;
            return new Response($response->status, ['dpop-nonce' => $this->apiNonce] + $response->headers, $response->body);
        }
        return $response;
    }

    /** @param array<string,string> $headers */
    private function answer(string $method, string $url, array $headers, ?string $body): Response
    {
        $headers = array_change_key_case($headers, CASE_LOWER);
        $this->requests[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body];
        if ($this->silent > 0) {
            $this->silent--;
            throw new TransportError('No answer (simulated).');
        }
        $address = (string) strtok($url, '?');
        $path = (string) parse_url($url, PHP_URL_PATH);
        $key = $method . ' ' . $path;
        if (($this->instead[$key] ?? []) !== []) {
            return array_shift($this->instead[$key]);
        }
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        if (str_starts_with($url, self::ISSUER . '/')) {
            parse_str($body ?? '', $form);
            return match ($key) {
                'GET /.well-known/openid-configuration' => self::json(200, $this->discovery()),
                'GET /oauth2/jwks' => self::json(200, ['keys' => [['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => $this->idKeyId, 'use' => 'sig', 'alg' => 'EdDSA'] + $this->idKey->jwk()]]),
                'POST /oauth2/par' => $this->par($form),
                'POST /oauth2/token' => $this->token($form, $headers, $address),
                'POST /oauth2/revoke' => $this->revoke($form),
                default => self::json(404, ['error' => 'not_found']),
            };
        }
        if ($key === 'GET /v1/keys') {
            return self::json(200, ['object' => 'list', 'has_more' => false, 'data' => [
                ['id' => 'pol-2026', 'object' => 'key', 'use' => 'monetary_policy', 'algorithm' => 'Ed25519', 'public_key' => Key::generate()->publicKey(), 'status' => 'current'],
                ['id' => $this->eventKeyId, 'object' => 'key', 'use' => 'events', 'algorithm' => 'Ed25519', 'public_key' => $this->eventKey->publicKey(), 'status' => 'current'],
            ]]);
        }
        if ($key === 'GET /v1/status') {
            return self::json(200, ['object' => 'status', 'status' => 'operational', 'api_version' => '2026-11-10', 'livemode' => false, 'time' => $this->now]);
        }
        $token = $this->bearer($method, $address, $headers);
        if ($token instanceof Response) {
            return $token;
        }
        if ($key === 'GET /v1/me') {
            return self::json(200, ['id' => (string) $token['subject'], 'object' => 'user', 'name' => 'Ada Lovelace', 'locale' => 'en']);
        }
        if ($key === 'GET /v1/transfers') {
            // Seven transfers, ctx_7 the most recent.
            $after = isset($query['starting_after']) ? (int) substr((string) $query['starting_after'], 4) : 8;
            $limit = (int) ($query['limit'] ?? 10);
            $ids = array_slice(range($after - 1, 1), 0, $after > 1 ? $limit : 0);
            return self::json(200, ['object' => 'list', 'has_more' => $ids !== [] && min($ids) > 1, 'data' => array_map(static fn (int $n): array => ['id' => 'ctx_' . $n, 'object' => 'transfer', 'amount' => $n * 100], $ids)]);
        }
        if ($key === 'POST /v1/webhook_endpoints') {
            return self::json(201, ['id' => 'we_1', 'object' => 'webhook_endpoint', 'status' => 'enabled'] + (array) json_decode((string) $body, true));
        }
        if ($key === 'GET /v1/webhook_endpoints') {
            return self::json(200, ['object' => 'list', 'has_more' => false, 'data' => []]);
        }
        return self::json(404, ['error' => ['type' => 'invalid_request_error', 'code' => 'not_found', 'message' => 'No such address.', 'request_id' => 'req_fake']]);
    }

    /** @param array<string,mixed> $body */
    public static function json(int $status, array $body, array $headers = []): Response
    {
        return new Response($status, $headers + ['content-type' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    /** @return array<string,mixed> */
    public function discovery(): array
    {
        $i = self::ISSUER;
        return [
            'issuer' => $i, 'authorization_endpoint' => $i . '/oauth2/authorize', 'token_endpoint' => $i . '/oauth2/token',
            'pushed_authorization_request_endpoint' => $i . '/oauth2/par', 'revocation_endpoint' => $i . '/oauth2/revoke', 'jwks_uri' => $i . '/oauth2/jwks',
        ];
    }

    /** The code Naxa gives once the person allowed the pushed request $reference. */
    public function codeFor(string $reference): string
    {
        return 'code-for-' . substr($reference, -8);
    }

    /** An event as Naxa posts it: [body, Naxa-Signature]. @return array{0:string, 1:string} */
    public function delivery(array $event, ?int $at = null, ?Key $key = null, ?string $keyId = null): array
    {
        $body = json_encode($event, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $t = $at ?? $this->now;
        return [$body, 't=' . $t . ',kid=' . ($keyId ?? $this->eventKeyId) . ',ed25519=' . Jose::encode(($key ?? $this->eventKey)->sign($t . '.' . $body))];
    }

    // ------------------------------------------------------------------ Naxa ID

    /** @param array<string,mixed> $form */
    private function par(array $form): Response
    {
        if (($refusal = $this->client($form)) !== null) {
            return $refusal;
        }
        foreach (['redirect_uri', 'state', 'nonce', 'code_challenge', 'scope', 'dpop_jkt'] as $name) {
            if (!is_string($form[$name] ?? null) || $form[$name] === '') {
                return self::json(400, ['error' => 'invalid_request', 'error_description' => $name]);
            }
        }
        if (($form['response_type'] ?? null) !== 'code' || ($form['code_challenge_method'] ?? null) !== 'S256' || !in_array('openid', explode(' ', $form['scope']), true)) {
            return self::json(400, ['error' => 'invalid_request']);
        }
        $reference = 'urn:ietf:params:oauth:request_uri:' . sprintf('%08d', ++$this->serial);
        $this->pushed[$reference] = $form;
        return self::json(201, ['request_uri' => $reference, 'expires_in' => 60]);
    }

    /**
     * @param array<string,mixed> $form
     * @param array<string,string> $headers
     */
    private function token(array $form, array $headers, string $address): Response
    {
        if (($refusal = $this->client($form)) !== null) {
            return $refusal;
        }
        $jkt = $this->proof($headers['dpop'] ?? null, 'POST', $address, null, $this->idNonce);
        if ($jkt === null) {
            return $this->nonceMissing
                ? self::json(400, ['error' => 'use_dpop_nonce', 'error_description' => 'A proof must carry the nonce given.'], ['DPoP-Nonce' => (string) $this->idNonce])
                : self::json(400, ['error' => 'invalid_dpop_proof']);
        }
        $grant = $form['grant_type'] ?? '';
        if ($grant === 'client_credentials') {
            return self::json(200, ['access_token' => $this->issue($jkt, 'application', null), 'token_type' => $this->tokenType, 'expires_in' => $this->accessTokenTtl, 'scope' => 'application']);
        }
        if ($grant === 'refresh_token') {
            $kept = $this->refreshTokens[(string) ($form['refresh_token'] ?? '')] ?? null;
            if ($kept === null) {
                return self::json(400, ['error' => 'invalid_grant']);
            }
            $new = [];
            if ($this->rotates) {
                unset($this->refreshTokens[(string) $form['refresh_token']]);
                $new = ['refresh_token' => 'refresh-' . ++$this->serial];
                $this->refreshTokens[$new['refresh_token']] = $kept;
            }
            return self::json(200, ['access_token' => $this->issue($jkt, $kept['scope'], 'usr_ada'), 'token_type' => $this->tokenType, 'expires_in' => $this->accessTokenTtl, 'scope' => $kept['scope']] + $new);
        }
        foreach ($this->pushed as $reference => $request) {
            if ($this->codeFor($reference) !== ($form['code'] ?? null)) {
                continue;
            }
            unset($this->pushed[$reference]);
            if (($form['redirect_uri'] ?? null) !== $request['redirect_uri']
                || !hash_equals($request['code_challenge'], Jose::encode(hash('sha256', (string) ($form['code_verifier'] ?? ''), true)))
                || !hash_equals($request['dpop_jkt'], $jkt)) {
                return self::json(400, ['error' => 'invalid_grant', 'error_description' => 'pkce_failed']);
            }
            $refresh = 'refresh-' . ++$this->serial;
            $this->refreshTokens[$refresh] = ['scope' => $request['scope']];
            $claims = array_filter($this->idTokenClaims + [
                'iss' => self::ISSUER, 'sub' => 'usr_ada', 'aud' => $this->clientId, 'azp' => $this->clientId,
                'iat' => $this->now, 'exp' => $this->now + 600, 'nonce' => $request['nonce'], 'name' => 'Ada Lovelace',
            ], static fn (mixed $v): bool => $v !== null);
            return self::json(200, [
                'access_token' => $this->issue($jkt, $request['scope'], 'usr_ada'), 'token_type' => $this->tokenType, 'expires_in' => $this->accessTokenTtl,
                'scope' => $request['scope'], 'refresh_token' => $refresh,
                'id_token' => Jose::sign(['typ' => 'JWT', 'kid' => $this->idKeyId], $claims, $this->idTokenSignedWith ?? $this->idKey),
            ]);
        }
        return self::json(400, ['error' => 'invalid_grant']);
    }

    /** @param array<string,mixed> $form */
    private function revoke(array $form): Response
    {
        if (($refusal = $this->client($form)) !== null) {
            return $refusal;
        }
        unset($this->refreshTokens[(string) ($form['token'] ?? '')], $this->accessTokens[(string) ($form['token'] ?? '')]);
        return self::json(200, []);
    }

    private function issue(string $jkt, string $scope, ?string $subject): string
    {
        $token = 'access-' . ++$this->serial;
        $this->accessTokens[$token] = ['jkt' => $jkt, 'scope' => $scope, 'subject' => $subject];
        return $token;
    }

    /**
     * The application says who it is (private_key_jwt), as Naxa ID checks it.
     *
     * @param array<string,mixed> $form
     */
    private function client(array $form): ?Response
    {
        $refused = static fn (string $why): Response => self::json(401, ['error' => 'invalid_client', 'error_description' => $why]);
        if (($form['client_assertion_type'] ?? null) !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' || !is_string($form['client_assertion'] ?? null)) {
            return $refused('private_key_jwt_required');
        }
        $public = base64_decode($this->clientPublicKey, true);
        $verified = Jose::verify($form['client_assertion'], fn (string $kid): ?string => $kid === $this->clientKeyId ? $public : null);
        if ($verified === null) {
            return $refused('assertion_signature');
        }
        $c = $verified[1];
        if (($c['iss'] ?? null) !== $this->clientId || ($c['sub'] ?? null) !== $this->clientId || ($c['aud'] ?? null) !== self::ISSUER
            || !is_int($c['exp'] ?? null) || $c['exp'] < $this->now || $c['exp'] > $this->now + 300
            || !is_string($c['jti'] ?? null) || isset($this->seen['a:' . $c['jti']])) {
            return $refused('assertion_claims');
        }
        $this->seen['a:' . $c['jti']] = true;
        return null;
    }

    /**
     * A proof of possession (RFC 9449), as Naxa checks it.
     *
     * @return ?string the thumbprint of the key that signed it; null when the proof is refused
     */
    private function proof(?string $proof, string $method, string $address, ?string $token, ?string $nonce = null): ?string
    {
        $this->nonceMissing = false;
        $parts = explode('.', (string) $proof);
        if (count($parts) !== 3) {
            return null;
        }
        $header = json_decode((string) Jose::decode($parts[0]), true);
        $claims = json_decode((string) Jose::decode($parts[1]), true);
        $signature = (string) Jose::decode($parts[2]);
        $x = is_array($header) ? Jose::decode((string) ($header['jwk']['x'] ?? '')) : null;
        if (!is_array($header) || !is_array($claims) || ($header['typ'] ?? null) !== 'dpop+jwt' || ($header['alg'] ?? null) !== 'EdDSA' || isset($header['jwk']['d'])
            || $x === null || strlen($x) !== 32 || strlen($signature) !== 64 || !sodium_crypto_sign_verify_detached($signature, $parts[0] . '.' . $parts[1], $x)) {
            return null;
        }
        if (($claims['htm'] ?? null) !== $method || ($claims['htu'] ?? null) !== $address
            || !is_int($claims['iat'] ?? null) || abs($claims['iat'] - $this->now) > 60
            || !is_string($claims['jti'] ?? null) || strlen($claims['jti']) < 16 || isset($this->seen['p:' . $claims['jti']])
            || ($token !== null && ($claims['ath'] ?? null) !== Jose::encode(hash('sha256', $token, true)))) {
            return null;
        }
        if ($nonce !== null && ($claims['nonce'] ?? null) !== $nonce) {
            $this->nonceMissing = true;
            return null;
        }
        $this->seen['p:' . $claims['jti']] = true;
        return Jose::encode(hash('sha256', '{"crv":"Ed25519","kty":"OKP","x":"' . Jose::encode($x) . '"}', true));
    }

    /**
     * @param array<string,string> $headers
     * @return array{jkt:string, scope:string, subject:?string}|Response the token's record, or the refusal
     */
    private function bearer(string $method, string $address, array $headers): array|Response
    {
        $refused = static fn (int $status, string $type, string $code): Response => self::json($status, ['error' => ['type' => $type, 'code' => $code, 'message' => 'Refused: ' . $code . '.', 'request_id' => 'req_fake']], ['x-request-id' => 'req_fake']);
        $authorization = $headers['authorization'] ?? '';
        if (!str_starts_with($authorization, 'DPoP ')) {
            return $refused(401, 'authentication_error', 'invalid_token');
        }
        $token = substr($authorization, 5);
        $record = $this->accessTokens[$token] ?? null;
        if ($record === null) {
            return $refused(401, 'authentication_error', 'invalid_token');
        }
        $jkt = $this->proof($headers['dpop'] ?? null, $method, $address, $token, $this->apiNonce);
        if ($jkt === null && $this->nonceMissing) {
            return self::json(401, ['error' => ['type' => 'authentication_error', 'code' => 'invalid_dpop_proof', 'message' => 'Refused: a proof must carry the nonce given.', 'request_id' => 'req_fake']],
                ['x-request-id' => 'req_fake', 'www-authenticate' => 'DPoP error="use_dpop_nonce", error_description="A proof must carry the nonce given."', 'dpop-nonce' => (string) $this->apiNonce]);
        }
        if ($jkt === null || !hash_equals($record['jkt'], $jkt)) {
            return $refused(401, 'authentication_error', 'invalid_dpop_proof');
        }
        return $record;
    }
}
