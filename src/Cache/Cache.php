<?php

declare(strict_types=1);

namespace Naxa\Sdk\Cache;

/**
 * Where the SDK keeps, between two requests, what it would otherwise ask Naxa each time: Naxa's
 * public keys, its addresses, the application's own access token. Nothing in it is a key of the
 * application; the access token it holds is bound to the application's key and worth nothing
 * without it.
 */
interface Cache
{
    public function get(string $key): ?string;

    /** @param int $ttl seconds */
    public function set(string $key, string $value, int $ttl): void;

    public function delete(string $key): void;
}
