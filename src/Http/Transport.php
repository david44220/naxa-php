<?php

declare(strict_types=1);

namespace Naxa\Sdk\Http;

use Naxa\Sdk\Exception\TransportError;

/**
 * How a request reaches Naxa. CurlTransport is the default; another one (a company's own HTTP
 * client, a recorder for tests) only has to send what it is given, unchanged, follow no
 * redirect and verify the server's certificate.
 */
interface Transport
{
    /**
     * @param array<string,string> $headers
     * @throws TransportError when no answer could be read
     */
    public function send(string $method, string $url, array $headers = [], ?string $body = null): Response;
}
