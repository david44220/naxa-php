<?php

declare(strict_types=1);

namespace Naxa\Sdk\Internal;

use Naxa\Sdk\Cache\Cache;
use Naxa\Sdk\Exception\ApiError;
use Naxa\Sdk\Exception\ConfigurationError;
use Naxa\Sdk\Exception\TransportError;
use Naxa\Sdk\Http\Response;
use Naxa\Sdk\Http\Transport;
use Naxa\Sdk\Key;
use Naxa\Sdk\Naxa;

/**
 * What every part of the SDK shares: where Naxa is, how requests leave, what is remembered,
 * what time it is, and when a request is sent again.
 *
 * @internal
 */
final class Connection
{
    /** A request that may be sent again is not sent again when Naxa asks to wait longer than this (seconds). */
    private const MAX_WAIT = 3;
    /** How long a server's nonce is kept between two requests (seconds). A nonce that has aged is simply given again. */
    private const NONCE_TTL = 600;

    public readonly string $apiBase;
    /** @var array<string,?string> the nonce each server last asked proofs of possession to carry, by origin */
    private array $nonces = [];

    /**
     * @param \Closure(): int $clock seconds since the Unix epoch
     * @param \Closure(int): void $sleep waits that many milliseconds
     */
    public function __construct(
        string $apiBase,
        public readonly Transport $transport,
        public readonly Cache $cache,
        private readonly \Closure $clock,
        private readonly \Closure $sleep,
        public readonly ?string $locale = null,
        public readonly int $maxRetries = 2,
    ) {
        $this->apiBase = self::address($apiBase, 'apiBase');
        if ($locale !== null && preg_match('/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/', $locale) !== 1) {
            throw new ConfigurationError('The locale must be a language tag such as "fr" or "pt-BR".');
        }
    }

    public function now(): int
    {
        return ($this->clock)();
    }

    /**
     * An address of Naxa as the SDK accepts it: https, or http on this very machine (a local
     * Naxa during development). Nothing leaves in clear on a network.
     */
    public static function address(string $url, string $name): string
    {
        $url = rtrim($url, '/');
        $p = parse_url($url);
        $host = is_array($p) ? strtolower((string) ($p['host'] ?? '')) : '';
        $local = $host === 'localhost' || str_ends_with($host, '.localhost') || $host === '127.0.0.1' || $host === '[::1]';
        $scheme = is_array($p) ? strtolower((string) ($p['scheme'] ?? '')) : '';
        if ($host === '' || isset($p['user']) || isset($p['query']) || isset($p['fragment']) || !($scheme === 'https' || ($scheme === 'http' && $local))) {
            throw new ConfigurationError("{$name} must be an https address (http is accepted for localhost only): {$url}");
        }
        return $url;
    }

    /**
     * Sends a request, again when it may be and it is worth it: no answer at all, or Naxa asking
     * to come back in a moment (429, 503). What is sent is built anew for each attempt, since a
     * proof of possession or a client assertion is used once.
     *
     * A server may ask proofs of possession to carry a value it chose (RFC 9449, section 8):
     * it refuses the request, done or not, and gives the value. The request is then sent once
     * more with it, whatever the request is, since nothing was done; the value is kept for the
     * requests that follow, and replaced whenever the server gives another.
     *
     * @param callable(): array{0: array<string,string>, 1: ?string} $build headers and body of one attempt
     */
    public function send(string $method, string $url, callable $build, bool $again): Response
    {
        $withNonce = false;
        for ($attempt = 0; ; $attempt++) {
            [$headers, $body] = $build();
            $proved = isset($headers['DPoP']);
            $headers += ['Accept' => 'application/json', 'User-Agent' => 'naxa-php/' . Naxa::VERSION];
            if ($this->locale !== null) {
                $headers += ['Accept-Language' => $this->locale];
            }
            $last = !$again || $attempt >= $this->maxRetries;
            try {
                $response = $this->transport->send($method, $url, $headers, $body);
            } catch (TransportError $e) {
                if ($last) {
                    throw $e;
                }
                ($this->sleep)(200 * (2 ** $attempt));
                continue;
            }
            if ($this->nonceGiven($url, $response) && $proved && !$withNonce && self::asksForNonce($response)) {
                // Not an attempt: the same request, now with what the server asked for.
                $withNonce = true;
                $attempt--;
                continue;
            }
            if ($last || !in_array($response->status, [429, 503], true)) {
                return $response;
            }
            $wait = $response->header('retry-after');
            $seconds = $wait !== null && ctype_digit($wait) ? (int) $wait : 1;
            if ($seconds > self::MAX_WAIT) {
                return $response;
            }
            ($this->sleep)($seconds * 1000);
        }
    }

    /**
     * A request to the API (/v1/...).
     *
     * @param array<string,string|int|null> $query
     * @param array<string,mixed>|null $body sent as JSON
     * @param ?string $token the access token the request is made with; none for what anyone reads
     * @param ?Key $proofKey the key the token is bound to
     * @return array<string,mixed> the object Naxa answered
     * @throws ApiError|TransportError
     */
    public function api(string $method, string $path, array $query = [], ?array $body = null, ?string $token = null, ?Key $proofKey = null, ?string $idempotencyKey = null): array
    {
        $address = $this->apiBase . $path;
        $query = array_filter($query, static fn (mixed $v): bool => $v !== null);
        $url = $address . ($query !== [] ? '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986) : '');
        $json = $body !== null ? json_encode((object) $body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null;
        $build = function () use ($method, $address, $json, $token, $proofKey, $idempotencyKey): array {
            $headers = ['Naxa-Version' => Naxa::API_VERSION];
            if ($token !== null && $proofKey !== null) {
                $headers['Authorization'] = 'DPoP ' . $token;
                $headers['DPoP'] = $this->proof($proofKey, $method, $address, $token);
            }
            if ($json !== null) {
                $headers['Content-Type'] = 'application/json';
            }
            if ($idempotencyKey !== null) {
                $headers['Idempotency-Key'] = $idempotencyKey;
            }
            return [$headers, $json];
        };
        // A read changes nothing, and a write with an idempotency key is done once however often it is sent.
        $response = $this->send($method, $url, $build, $method === 'GET' || $idempotencyKey !== null);
        $answer = $response->json();
        if ($response->status >= 200 && $response->status < 300 && $answer !== null) {
            return $answer;
        }
        $error = is_array($answer['error'] ?? null) ? $answer['error'] : null;
        if ($error === null || !is_string($error['code'] ?? null) || !is_string($error['type'] ?? null)) {
            throw new TransportError('An answer that is not the API\'s (HTTP ' . $response->status . ') from ' . (string) parse_url($url, PHP_URL_HOST) . '.');
        }
        $wait = $response->header('retry-after');
        throw new ApiError(
            is_string($error['message'] ?? null) ? $error['message'] : $error['code'],
            $response->status,
            $error['type'],
            $error['code'],
            is_string($error['param'] ?? null) ? $error['param'] : null,
            is_string($error['request_id'] ?? null) ? $error['request_id'] : $response->header('x-request-id'),
            $wait !== null && ctype_digit($wait) ? (int) $wait : null,
        );
    }

    /**
     * A proof of possession (DPoP, RFC 9449) for one request: this method, this address, now,
     * and this token when the request carries one. It is used once.
     */
    public function proof(Key $key, string $method, string $address, ?string $token = null): string
    {
        $claims = ['jti' => Jose::random(18), 'htm' => strtoupper($method), 'htu' => strtok($address, '?#'), 'iat' => $this->now()];
        if ($token !== null) {
            $claims['ath'] = Jose::encode(hash('sha256', $token, true));
        }
        $nonce = $this->nonce($address);
        if ($nonce !== null) {
            $claims['nonce'] = $nonce;
        }
        return Jose::sign(['typ' => 'dpop+jwt', 'jwk' => $key->jwk()], $claims, $key);
    }

    /** The nonce the server at this address last gave, if it gave one. */
    private function nonce(string $address): ?string
    {
        $origin = self::origin($address);
        if (!array_key_exists($origin, $this->nonces)) {
            $kept = $this->cache->get('dpop-nonce:' . $origin);
            $this->nonces[$origin] = $kept !== null && self::isNonce($kept) ? $kept : null;
        }
        return $this->nonces[$origin];
    }

    /** Keeps the nonce an answer gives. Whether it gave one. */
    private function nonceGiven(string $url, Response $response): bool
    {
        $nonce = $response->header('dpop-nonce');
        if ($nonce === null || !self::isNonce($nonce)) {
            return false;
        }
        $origin = self::origin($url);
        if (($this->nonces[$origin] ?? null) !== $nonce) {
            $this->nonces[$origin] = $nonce;
            $this->cache->set('dpop-nonce:' . $origin, $nonce, self::NONCE_TTL);
        }
        return true;
    }

    /** Whether a refusal is the server asking for its nonce: from Naxa ID (400) or from the API (401). */
    private static function asksForNonce(Response $response): bool
    {
        if ($response->status === 401) {
            return preg_match('/\berror="?use_dpop_nonce\b/', (string) $response->header('www-authenticate')) === 1;
        }
        return $response->status === 400 && ($response->json()['error'] ?? null) === 'use_dpop_nonce';
    }

    /** What RFC 9449 allows a nonce to be, and no longer than a header should be. */
    private static function isNonce(string $value): bool
    {
        return preg_match('/^[\x21\x23-\x5b\x5d-\x7e]{1,255}$/', $value) === 1;
    }

    private static function origin(string $url): string
    {
        $p = parse_url($url);
        return strtolower(($p['scheme'] ?? '') . '://' . ($p['host'] ?? '') . (isset($p['port']) ? ':' . $p['port'] : ''));
    }

    /**
     * Something Naxa publishes and the SDK keeps for a while (its addresses, its public keys).
     *
     * @return array<string|int,mixed>
     * @throws TransportError
     */
    public function published(string $url, int $ttl, bool $fresh = false): array
    {
        $key = 'published:' . $url;
        $cached = $fresh ? null : $this->cache->get($key);
        $document = $cached !== null ? json_decode($cached, true, 32) : null;
        if (is_array($document)) {
            return $document;
        }
        $response = $this->send('GET', $url, static fn (): array => [['Naxa-Version' => Naxa::API_VERSION], null], true);
        $document = $response->json();
        if ($response->status !== 200 || $document === null) {
            throw new TransportError('Naxa did not answer what it publishes at ' . $url . ' (HTTP ' . $response->status . ').');
        }
        $this->cache->set($key, $response->body, $ttl);
        return $document;
    }
}
