<?php

declare(strict_types=1);

namespace Naxa\Sdk;

use Naxa\Sdk\Exception\ConfigurationError;

/**
 * What an application holds for one person who allowed it: a short-lived access token, the
 * refresh token that obtains the next ones while the person is away, and what Naxa ID signed
 * about the person when they signed in.
 *
 * Both tokens are bound to the application's key and useless without it. They are still the
 * person's access: keep them on the server (toArray(), fromArray()), encrypted at rest when
 * they outlive the session, and never send them to a browser.
 */
final class TokenSet
{
    /**
     * @param list<string> $scopes what the person allowed
     * @param array<string,mixed> $claims what Naxa ID signed at sign-in (`sub` is the person, under an identifier of this application's own)
     */
    public function __construct(
        #[\SensitiveParameter] public readonly string $accessToken,
        /** Seconds since the Unix epoch. */
        public readonly int $expiresAt,
        public readonly array $scopes,
        #[\SensitiveParameter] public readonly ?string $refreshToken = null,
        public readonly array $claims = [],
    ) {
    }

    /** The person, under the identifier this application knows them by (`usr_...`). The same at each sign-in, different for another application. */
    public function subject(): ?string
    {
        return is_string($this->claims['sub'] ?? null) ? $this->claims['sub'] : null;
    }

    public function allows(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /** @return array<string,mixed> what to keep on the server */
    public function toArray(): array
    {
        return ['access_token' => $this->accessToken, 'expires_at' => $this->expiresAt, 'scopes' => $this->scopes, 'refresh_token' => $this->refreshToken, 'claims' => $this->claims];
    }

    /** @param array<string,mixed> $stored what toArray() gave */
    public static function fromArray(array $stored): self
    {
        if (!is_string($stored['access_token'] ?? null) || $stored['access_token'] === '') {
            throw new ConfigurationError('Not a token set kept by this SDK: "access_token" is missing.');
        }
        return new self(
            $stored['access_token'],
            (int) ($stored['expires_at'] ?? 0),
            array_values(array_filter((array) ($stored['scopes'] ?? []), 'is_string')),
            is_string($stored['refresh_token'] ?? null) && $stored['refresh_token'] !== '' ? $stored['refresh_token'] : null,
            is_array($stored['claims'] ?? null) ? $stored['claims'] : [],
        );
    }

    /** A dump or a log never shows a token. */
    public function __debugInfo(): array
    {
        return ['subject' => $this->subject(), 'scopes' => $this->scopes, 'expires_at' => $this->expiresAt, 'refreshable' => $this->refreshToken !== null];
    }
}
