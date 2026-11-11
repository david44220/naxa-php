<?php

declare(strict_types=1);

namespace Naxa\Sdk\Http;

/** What Naxa answered. */
final class Response
{
    /** @var array<string,string> names in lower case */
    public readonly array $headers;

    /** @param array<string,string> $headers */
    public function __construct(public readonly int $status, array $headers, public readonly string $body)
    {
        $this->headers = array_change_key_case($headers, CASE_LOWER);
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /** @return array<string|int,mixed>|null the body when it is a JSON object or list */
    public function json(): ?array
    {
        $decoded = json_decode($this->body, true, 64);
        return is_array($decoded) ? $decoded : null;
    }
}
