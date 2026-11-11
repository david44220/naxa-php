<?php

declare(strict_types=1);

namespace Naxa\Sdk\Http;

use Naxa\Sdk\Exception\TransportError;

/**
 * HTTPS with PHP's curl extension: the server's certificate is verified, no redirect is
 * followed, and an answer larger than Naxa ever sends is not read to its end.
 */
final class CurlTransport implements Transport
{
    private const MAX_BODY = 2_097_152;

    public function __construct(private readonly int $timeout = 15, private readonly int $connectTimeout = 5)
    {
    }

    public function send(string $method, string $url, array $headers = [], ?string $body = null): Response
    {
        $lines = [];
        foreach ($headers as $name => $value) {
            if (preg_match('/[\r\n]/', $name . $value) === 1) {
                throw new TransportError('A header may not hold a line break.');
            }
            $lines[] = $name . ': ' . $value;
        }
        // curl would add these by itself.
        $lines[] = 'Expect:';
        $received = [];
        $content = '';
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$received): int {
                $at = strpos($line, ':');
                if ($at !== false) {
                    $received[strtolower(trim(substr($line, 0, $at)))] = trim(substr($line, $at + 1));
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$content): int {
                if (strlen($content) + strlen($chunk) > self::MAX_BODY) {
                    return 0;
                }
                $content .= $chunk;
                return strlen($chunk);
            },
        ]);
        // Nothing but HTTP: no file://, no gopher://, whatever the address says.
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            curl_setopt($curl, CURLOPT_PROTOCOLS_STR, 'https,http');
        } else {
            curl_setopt($curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS | CURLPROTO_HTTP);
        }
        if ($body !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }
        $done = curl_exec($curl);
        $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $error = curl_error($curl);
        unset($curl);
        if ($done === false || $status === 0) {
            throw new TransportError('No answer from ' . (string) parse_url($url, PHP_URL_HOST) . ($error !== '' ? ': ' . $error : '.'));
        }
        return new Response($status, $received, $content);
    }
}
