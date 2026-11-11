<?php

declare(strict_types=1);

namespace Naxa\Sdk\Exception;

/**
 * A refusal of the API (https://developers.naxacorp.com, "Errors"). $errorCode says what
 * exactly was refused and never changes with the language; the message is for a developer.
 */
final class ApiError extends NaxaException
{
    public function __construct(
        string $message,
        /** The HTTP status of the answer. */
        public readonly int $status,
        /** The family of the refusal: invalid_request_error, authentication_error, permission_error, conflict_error, idempotency_error, rate_limit_error, api_error. */
        public readonly string $type,
        /** What exactly was refused: invalid_token, insufficient_scope, rate_limited, resource_missing... */
        public readonly string $errorCode,
        /** The parameter, the field or the header the refusal is about, when it is about one. */
        public readonly ?string $param = null,
        /** To quote when contacting the support. */
        public readonly ?string $requestId = null,
        /** In how many seconds to come back, when Naxa says so (rate limits, a busy service). */
        public readonly ?int $retryAfter = null,
    ) {
        parent::__construct($message, $status);
    }

    /** The person's consent or the token is gone: the person has to sign in with Naxa again. */
    public function needsNewAuthorization(): bool
    {
        return $this->errorCode === 'invalid_token';
    }
}
