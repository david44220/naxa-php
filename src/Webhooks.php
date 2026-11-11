<?php

declare(strict_types=1);

namespace Naxa\Sdk;

use Naxa\Sdk\Exception\SignatureError;
use Naxa\Sdk\Exception\TransportError;
use Naxa\Sdk\Internal\Connection;
use Naxa\Sdk\Internal\Jose;

/**
 * Verifies the events Naxa posts to the application's addresses.
 *
 *     $payload = file_get_contents('php://input');
 *     try {
 *         $event = $naxa->webhooks()->verify($payload, $_SERVER['HTTP_NAXA_SIGNATURE'] ?? '');
 *     } catch (SignatureError) {
 *         http_response_code(400);
 *         exit;
 *     }
 *     // $event['id'] was already handled? Answer 204 and stop: Naxa delivers at least once.
 *
 * Naxa signs each delivery with a key of its own and publishes the public half (GET /v1/keys):
 * no secret is shared, and the address of the application proves nothing to whoever finds it.
 * The address that called proves nothing either: only the signature does.
 */
final class Webhooks
{
    /** @internal use Naxa::webhooks() */
    public function __construct(private readonly Connection $connection)
    {
    }

    /**
     * @param string $payload the body of the request, byte for byte as it was received (never decoded and encoded again)
     * @param string $signature the `Naxa-Signature` header
     * @param int $tolerance how old a delivery may be, in seconds
     * @return array<string,mixed> the event
     * @throws SignatureError when this is not an event Naxa signed recently
     * @throws TransportError when Naxa's public keys cannot be read (answer 5xx: Naxa will deliver again)
     */
    public function verify(string $payload, string $signature, int $tolerance = 300): array
    {
        if (preg_match('/^t=([0-9]{1,12}),kid=([a-z0-9-]{1,64}),ed25519=([A-Za-z0-9_-]{86})$/', $signature, $m) !== 1) {
            throw new SignatureError('header_malformed');
        }
        [, $instant, $keyId, $encoded] = $m;
        if (abs($this->connection->now() - (int) $instant) > max(1, $tolerance)) {
            throw new SignatureError('too_old');
        }
        $key = $this->eventKeys(false)[$keyId] ?? null;
        // Naxa changed its key since the list was kept: ask once more.
        $key ??= $this->eventKeys(true)[$keyId] ?? null;
        if ($key === null) {
            throw new SignatureError('key_unknown');
        }
        $raw = Jose::decode($encoded);
        if ($raw === null || strlen($raw) !== SODIUM_CRYPTO_SIGN_BYTES || !sodium_crypto_sign_verify_detached($raw, $instant . '.' . $payload, $key)) {
            throw new SignatureError('signature_invalid');
        }
        $event = json_decode($payload, true, 32);
        if (!is_array($event) || !is_string($event['id'] ?? null) || !is_string($event['type'] ?? null)) {
            throw new SignatureError('payload_invalid');
        }
        return $event;
    }

    /** @return array<string,string> the public keys Naxa signs events with, by their identifier (32 bytes each) */
    private function eventKeys(bool $fresh): array
    {
        $list = $this->connection->published($this->connection->apiBase . '/v1/keys', 300, $fresh);
        $keys = [];
        foreach ((array) ($list['data'] ?? []) as $key) {
            if (!is_array($key) || ($key['use'] ?? null) !== 'events' || ($key['algorithm'] ?? null) !== 'Ed25519' || !is_string($key['id'] ?? null) || !is_string($key['public_key'] ?? null)) {
                continue;
            }
            $raw = base64_decode($key['public_key'], true);
            if ($raw !== false && strlen($raw) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                $keys[$key['id']] = $raw;
            }
        }
        return $keys;
    }
}
