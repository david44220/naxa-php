<?php

declare(strict_types=1);

namespace Naxa\Sdk\Exception;

/**
 * A refusal of Naxa ID (the authorization server), in OAuth's own words: invalid_client,
 * invalid_grant, invalid_dpop_proof, invalid_scope... $description is Naxa's precision, a code
 * and not a sentence (pkce_failed, assertion_claims...).
 */
final class OAuthError extends NaxaException
{
    public function __construct(
        public readonly string $error,
        public readonly ?string $description = null,
        public readonly int $status = 400,
    ) {
        parent::__construct('Naxa ID refused the request: ' . $error . ($description !== null && $description !== '' ? ' (' . $description . ')' : ''), $status);
    }

    /** The code or the refresh token is no longer worth anything: the person has to sign in with Naxa again. */
    public function needsNewAuthorization(): bool
    {
        return $this->error === 'invalid_grant';
    }
}
