<?php

declare(strict_types=1);

namespace Naxa\Sdk;

use Naxa\Sdk\Cache\Cache;
use Naxa\Sdk\Cache\MemoryCache;
use Naxa\Sdk\Exception\ApiError;
use Naxa\Sdk\Exception\TransportError;
use Naxa\Sdk\Http\CurlTransport;
use Naxa\Sdk\Http\Transport;
use Naxa\Sdk\Internal\Connection;

/**
 * What anyone reads, without an application or a key: the supply of NXA, the policies in
 * force, Naxa's public keys, the state of the API. Amounts are integers in minor units
 * (100 is 1 NXA).
 *
 *     $supply = PublicData::of()->supply();          // no application needed
 *     $supply = $naxa->publicData()->supply();       // the same, from an application
 */
final class PublicData
{
    /** @internal use PublicData::of() or Naxa::publicData() */
    public function __construct(private readonly Connection $connection)
    {
    }

    /** @param string $apiBase another address for a sandbox */
    public static function of(string $apiBase = Naxa::API, ?Transport $transport = null, ?Cache $cache = null, ?string $locale = null): self
    {
        return new self(new Connection(
            $apiBase,
            $transport ?? new CurlTransport(),
            $cache ?? new MemoryCache(),
            static fn (): int => time(),
            static function (int $milliseconds): void {
                usleep($milliseconds * 1000);
            },
            $locale,
        ));
    }

    /**
     * Whether the API answers and in which state (`operational`, `maintenance`, `degraded`,
     * `outage`), and whether this is the real ledger (`livemode`).
     *
     * @return array<string,mixed>
     * @throws ApiError|TransportError
     */
    public function status(): array
    {
        return $this->connection->api('GET', '/v1/status');
    }

    /**
     * How many NXA exist and where they are.
     *
     * @return array<string,mixed>
     * @throws ApiError|TransportError
     */
    public function supply(): array
    {
        return $this->connection->api('GET', '/v1/supply');
    }

    /**
     * Each issuance and destruction of NXA, the most recent first.
     *
     * @throws ApiError|TransportError
     */
    public function supplyEvents(int $limit = 10, ?string $startingAfter = null): Page
    {
        return Page::of(
            $this->connection->api('GET', '/v1/supply/events', ['limit' => $limit, 'starting_after' => $startingAfter]),
            fn (string $last): Page => $this->supplyEvents($limit, $last),
        );
    }

    /**
     * The monetary policy in force, as Naxa signed it.
     *
     * @return array<string,mixed>
     * @throws ApiError|TransportError
     */
    public function monetaryPolicy(): array
    {
        return $this->connection->api('GET', '/v1/monetary-policy');
    }

    /**
     * The fee policy in force.
     *
     * @return array<string,mixed>
     * @throws ApiError|TransportError
     */
    public function feePolicy(): array
    {
        return $this->connection->api('GET', '/v1/fee-policies/current');
    }

    /**
     * The public keys Naxa signs with (events, policies).
     *
     * @throws ApiError|TransportError
     */
    public function keys(): Page
    {
        return Page::of($this->connection->api('GET', '/v1/keys'));
    }
}
