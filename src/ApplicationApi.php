<?php

declare(strict_types=1);

namespace Naxa\Sdk;

use Naxa\Sdk\Exception\ApiError;
use Naxa\Sdk\Exception\OAuthError;
use Naxa\Sdk\Exception\TransportError;
use Naxa\Sdk\Internal\Connection;
use Naxa\Sdk\Internal\Jose;

/**
 * The application's own resources, in no one's name: the addresses Naxa posts its events to,
 * and the events themselves, to read back what a server missed.
 *
 * Every write is sent with an idempotency key: sent twice (a timeout, a retry), it is done
 * once. The SDK chooses one per call; give your own to make a write of yours safe to repeat
 * across processes.
 */
final class ApplicationApi
{
    /** @internal use Naxa::application() */
    public function __construct(private readonly Connection $connection, private readonly Naxa $naxa, private readonly Key $proofKey)
    {
    }

    /**
     * The addresses Naxa posts the application's events to.
     *
     * @throws ApiError|OAuthError|TransportError
     */
    public function webhookEndpoints(): Page
    {
        return Page::of($this->call('GET', '/v1/webhook_endpoints'));
    }

    /**
     * A new address for events: https, a host name, no fragment.
     *
     * @param list<string> $eventTypes the families asked for: `authorization.*`, `transfer.*`
     * @return array<string,mixed> the endpoint
     * @throws ApiError|OAuthError|TransportError
     */
    public function createWebhookEndpoint(string $url, array $eventTypes, ?string $idempotencyKey = null): array
    {
        return $this->call('POST', '/v1/webhook_endpoints', [], ['url' => $url, 'event_types' => array_values($eventTypes)], $idempotencyKey ?? Jose::random(18));
    }

    /**
     * @return array<string,mixed>
     * @throws ApiError|OAuthError|TransportError
     */
    public function webhookEndpoint(string $id): array
    {
        return $this->call('GET', '/v1/webhook_endpoints/' . rawurlencode($id));
    }

    /**
     * Changes an address, what it receives, or pauses it; what is left null does not change.
     *
     * @param list<string>|null $eventTypes
     * @param ?bool $disabled true pauses the address, false resumes it
     * @return array<string,mixed> the endpoint
     * @throws ApiError|OAuthError|TransportError
     */
    public function updateWebhookEndpoint(string $id, ?string $url = null, ?array $eventTypes = null, ?bool $disabled = null, ?string $idempotencyKey = null): array
    {
        $changes = array_filter(['url' => $url, 'event_types' => $eventTypes !== null ? array_values($eventTypes) : null, 'disabled' => $disabled], static fn (mixed $v): bool => $v !== null);
        return $this->call('POST', '/v1/webhook_endpoints/' . rawurlencode($id), [], $changes, $idempotencyKey ?? Jose::random(18));
    }

    /**
     * @return array<string,mixed>
     * @throws ApiError|OAuthError|TransportError
     */
    public function deleteWebhookEndpoint(string $id, ?string $idempotencyKey = null): array
    {
        return $this->call('DELETE', '/v1/webhook_endpoints/' . rawurlencode($id), [], null, $idempotencyKey ?? Jose::random(18));
    }

    /**
     * The application's events, the most recent first: what Naxa also posts to its addresses.
     * $endingBefore gives the events that came after one already seen, to catch up.
     *
     * @param ?string $type only the events of this type (`authorization.granted`, `authorization.revoked`, `transfer.completed`)
     * @throws ApiError|OAuthError|TransportError
     */
    public function events(?string $type = null, int $limit = 10, ?string $startingAfter = null, ?string $endingBefore = null): Page
    {
        return Page::of(
            $this->call('GET', '/v1/events', ['type' => $type, 'limit' => $limit, 'starting_after' => $startingAfter, 'ending_before' => $endingBefore]),
            $endingBefore === null ? fn (string $last): Page => $this->events($type, $limit, $last) : null,
        );
    }

    /**
     * @return array<string,mixed>
     * @throws ApiError|OAuthError|TransportError
     */
    public function event(string $id): array
    {
        return $this->call('GET', '/v1/events/' . rawurlencode($id));
    }

    /**
     * @param array<string,string|int|null> $query
     * @param array<string,mixed>|null $body
     * @return array<string,mixed>
     */
    private function call(string $method, string $path, array $query = [], ?array $body = null, ?string $idempotencyKey = null): array
    {
        try {
            return $this->connection->api($method, $path, $query, $body, $this->naxa->applicationToken(), $this->proofKey, $idempotencyKey);
        } catch (ApiError $e) {
            if ($e->errorCode !== 'invalid_token') {
                throw $e;
            }
            // The token kept in the cache is no longer worth anything: a new one, one more try.
            return $this->connection->api($method, $path, $query, $body, $this->naxa->applicationToken(true), $this->proofKey, $idempotencyKey);
        }
    }
}
