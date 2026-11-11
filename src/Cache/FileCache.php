<?php

declare(strict_types=1);

namespace Naxa\Sdk\Cache;

use Naxa\Sdk\Exception\ConfigurationError;

/**
 * Kept in files of a directory only the application's server reads (never under the web root):
 * what one request learnt serves the next ones. Each file is written whole or not at all and is
 * readable by its owner only.
 */
final class FileCache implements Cache
{
    private readonly string $directory;

    public function __construct(string $directory)
    {
        $this->directory = rtrim($directory, '/');
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            throw new ConfigurationError('The cache directory cannot be created: ' . $this->directory);
        }
    }

    public function get(string $key): ?string
    {
        $path = $this->path($key);
        $content = is_file($path) ? @file_get_contents($path) : false;
        if ($content === false) {
            return null;
        }
        $at = strpos($content, "\n");
        if ($at === false || (int) substr($content, 0, $at) <= time()) {
            return null;
        }
        return substr($content, $at + 1);
    }

    public function set(string $key, string $value, int $ttl): void
    {
        $path = $this->path($key);
        $temporary = $path . '.' . bin2hex(random_bytes(6));
        // A cache that cannot be written is a slower application, not a broken one.
        if (@file_put_contents($temporary, (time() + $ttl) . "\n" . $value, LOCK_EX) === false) {
            return;
        }
        @chmod($temporary, 0600);
        if (!@rename($temporary, $path)) {
            @unlink($temporary);
        }
    }

    public function delete(string $key): void
    {
        $path = $this->path($key);
        if (is_file($path)) {
            @unlink($path);
        }
    }

    private function path(string $key): string
    {
        return $this->directory . '/naxa-' . hash('sha256', $key) . '.cache';
    }
}
