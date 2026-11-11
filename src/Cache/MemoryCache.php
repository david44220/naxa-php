<?php

declare(strict_types=1);

namespace Naxa\Sdk\Cache;

/** Kept for the life of the PHP process: one HTTP request under PHP-FPM, much longer in a worker. */
final class MemoryCache implements Cache
{
    /** @var array<string, array{0:string, 1:int}> */
    private array $entries = [];

    public function get(string $key): ?string
    {
        $entry = $this->entries[$key] ?? null;
        if ($entry === null || $entry[1] <= time()) {
            unset($this->entries[$key]);
            return null;
        }
        return $entry[0];
    }

    public function set(string $key, string $value, int $ttl): void
    {
        $this->entries[$key] = [$value, time() + $ttl];
    }

    public function delete(string $key): void
    {
        unset($this->entries[$key]);
    }
}
