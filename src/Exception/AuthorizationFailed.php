<?php

declare(strict_types=1);

namespace Naxa\Sdk\Exception;

/**
 * The person did not come back from Naxa with something the application can use.
 *
 * $reason is `access_denied` when the person refused, another OAuth error when Naxa refused
 * the request, or one of the SDK's own checks: `request_missing` (this session has no request
 * pending: the return address was opened by hand, or twice), `state_mismatch` (the answer does
 * not belong to this browser's request), `issuer_mismatch` (it does not come from Naxa),
 * `code_missing`, `id_token_invalid` (what Naxa ID signed could not be verified).
 */
final class AuthorizationFailed extends NaxaException
{
    public function __construct(public readonly string $reason, string $message = '')
    {
        parent::__construct($message !== '' ? $message : 'The authorization did not complete: ' . $reason);
    }

    /** The person said no: nothing is wrong, there is simply nothing to read. */
    public function refusedByThePerson(): bool
    {
        return $this->reason === 'access_denied';
    }
}
