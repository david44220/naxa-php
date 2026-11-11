<?php

declare(strict_types=1);

namespace Naxa\Sdk;

use Naxa\Sdk\Exception\ApiError;
use Naxa\Sdk\Exception\OAuthError;
use Naxa\Sdk\Exception\TransportError;
use Naxa\Sdk\Internal\Connection;

/**
 * What one person allowed the application to read: who they are, their wallets, what they
 * hold, their history. Each method needs the scope it names; without it the API answers
 * `insufficient_scope` (ApiError). Amounts are integers in minor units (100 is 1 NXA).
 *
 * The access token is renewed by itself when it has expired. When the person withdrew their
 * consent, the renewal fails with OAuthError `invalid_grant`: they have to sign in again.
 */
final class PersonApi
{
    /** @internal use Naxa::person() */
    public function __construct(
        private readonly Connection $connection,
        private readonly Naxa $naxa,
        private readonly Key $proofKey,
        private TokenSet $tokens,
        private readonly ?\Closure $onRefresh = null,
    ) {
    }

    /** The tokens as they are now: the ones given, or the renewed ones. */
    public function tokens(): TokenSet
    {
        return $this->tokens;
    }

    /**
     * The person: their identifier for this application, name and language; their e-mail with
     * the scope `email`. Scope: `profile`.
     *
     * @return array<string,mixed>
     * @throws ApiError|OAuthError|TransportError
     */
    public function me(): array
    {
        return $this->get('/v1/me');
    }

    /**
     * The person's wallets. Scope: `wallets:read`.
     *
     * @throws ApiError|OAuthError|TransportError
     */
    public function wallets(): Page
    {
        return Page::of($this->get('/v1/wallets'));
    }

    /**
     * What a wallet of the person holds. Scope: `wallets:read`.
     *
     * @return array<string,mixed>
     * @throws ApiError|OAuthError|TransportError
     */
    public function balance(string $walletId): array
    {
        return $this->get('/v1/wallets/' . rawurlencode($walletId) . '/balance');
    }

    /**
     * The movements of a wallet of the person (their main wallet when none is named), the most
     * recent first. Scope: `transfers:read`.
     *
     * @throws ApiError|OAuthError|TransportError
     */
    public function transfers(?string $walletId = null, int $limit = 10, ?string $startingAfter = null): Page
    {
        return Page::of(
            $this->get('/v1/transfers', ['wallet' => $walletId, 'limit' => $limit, 'starting_after' => $startingAfter]),
            fn (string $last): Page => $this->transfers($walletId, $limit, $last),
        );
    }

    /**
     * One movement of the person. Scope: `transfers:read`.
     *
     * @return array<string,mixed>
     * @throws ApiError|OAuthError|TransportError
     */
    public function transfer(string $transferId): array
    {
        return $this->get('/v1/transfers/' . rawurlencode($transferId));
    }

    /**
     * @param array<string,string|int|null> $query
     * @return array<string,mixed>
     */
    private function get(string $path, array $query = []): array
    {
        if ($this->tokens->refreshToken !== null && $this->tokens->expiresAt - 30 <= $this->connection->now()) {
            $this->renew();
        }
        try {
            return $this->connection->api('GET', $path, $query, null, $this->tokens->accessToken, $this->proofKey);
        } catch (ApiError $e) {
            // The token ended earlier than it said (revoked, another clock): one renewal, one more try.
            if ($e->errorCode !== 'invalid_token' || $this->tokens->refreshToken === null) {
                throw $e;
            }
            $this->renew();
            return $this->connection->api('GET', $path, $query, null, $this->tokens->accessToken, $this->proofKey);
        }
    }

    private function renew(): void
    {
        $this->tokens = $this->naxa->refresh($this->tokens);
        if ($this->onRefresh !== null) {
            ($this->onRefresh)($this->tokens);
        }
    }
}
