<?php

declare(strict_types=1);

namespace Naxa\Sdk\Exception;

/**
 * What was received is not an event Naxa signed, or not one it signed recently: answer 400 and
 * do nothing with it. $reason: `header_malformed`, `too_old`, `key_unknown`, `signature_invalid`,
 * `payload_invalid`.
 */
final class SignatureError extends NaxaException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct('Not an event signed by Naxa: ' . $reason);
    }
}
