<?php

declare(strict_types=1);

namespace Naxa\Sdk\Exception;

/** The SDK was given something it cannot work with: a key, an address, a parameter. Nothing was sent. */
final class ConfigurationError extends NaxaException
{
}
