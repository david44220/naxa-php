<?php

declare(strict_types=1);

namespace Naxa\Sdk\Exception;

/**
 * No answer could be read from Naxa: the network, a timeout, an answer that is not what Naxa
 * sends. Whether the request reached Naxa is not known; a write sent with an idempotency key
 * can be sent again with the same key.
 */
final class TransportError extends NaxaException
{
}
