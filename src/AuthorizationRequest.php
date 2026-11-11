<?php

declare(strict_types=1);

namespace Naxa\Sdk;

use Naxa\Sdk\Exception\ConfigurationError;

/**
 * A request for a person's authorization, as Naxa::begin() pushed it to Naxa: the address to
 * send the person's browser to, and what the application keeps in the person's session until
 * they come back (toArray(), fromArray()). It is worth nothing after $expiresAt, and for
 * another browser.
 */
final class AuthorizationRequest
{
    public function __construct(
        /** Where to send the person's browser. */
        public readonly string $url,
        public readonly string $state,
        public readonly string $nonce,
        #[\SensitiveParameter] public readonly string $codeVerifier,
        /** Seconds since the Unix epoch: the person has until then to start at Naxa. */
        public readonly int $expiresAt,
    ) {
    }

    /** @return array{url:string, state:string, nonce:string, code_verifier:string, expires_at:int} what to keep in the session */
    public function toArray(): array
    {
        return ['url' => $this->url, 'state' => $this->state, 'nonce' => $this->nonce, 'code_verifier' => $this->codeVerifier, 'expires_at' => $this->expiresAt];
    }

    /** @param array<string,mixed> $stored what toArray() gave */
    public static function fromArray(array $stored): self
    {
        foreach (['url', 'state', 'nonce', 'code_verifier'] as $name) {
            if (!is_string($stored[$name] ?? null) || $stored[$name] === '') {
                throw new ConfigurationError('Not an authorization request kept by this SDK: "' . $name . '" is missing.');
            }
        }
        return new self($stored['url'], $stored['state'], $stored['nonce'], $stored['code_verifier'], (int) ($stored['expires_at'] ?? 0));
    }

    public function __debugInfo(): array
    {
        return ['url' => $this->url, 'expires_at' => $this->expiresAt];
    }
}
