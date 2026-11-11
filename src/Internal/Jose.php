<?php

declare(strict_types=1);

namespace Naxa\Sdk\Internal;

use Naxa\Sdk\Key;

/**
 * Compact signed tokens (JWS, RFC 7515) with EdDSA over Ed25519, the only algorithm Naxa
 * uses: there is none to choose and none to confuse.
 *
 * @internal
 */
final class Jose
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** @return string|null null when $text is not base64url */
    public static function decode(string $text): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]*$/', $text) !== 1) {
            return null;
        }
        $bytes = base64_decode(strtr($text, '-_', '+/') . str_repeat('=', (4 - strlen($text) % 4) % 4), true);
        return $bytes === false ? null : $bytes;
    }

    /**
     * @param array<string,mixed> $header beyond `alg`
     * @param array<string,mixed> $claims
     */
    public static function sign(array $header, array $claims, Key $key): string
    {
        $flags = JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        $signed = self::encode(json_encode(['alg' => 'EdDSA'] + $header, $flags)) . '.' . self::encode(json_encode($claims, $flags));
        return $signed . '.' . self::encode($key->sign($signed));
    }

    /**
     * Reads a token signed with EdDSA by one of the keys $keyFor knows.
     *
     * @param callable(string): ?string $keyFor the 32 bytes of the public key a `kid` names, or null
     * @return array{0: array<string,mixed>, 1: array<string,mixed>}|null header and claims; null unless the signature is right
     */
    public static function verify(string $token, callable $keyFor): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3 || strlen($token) > 16384) {
            return null;
        }
        [$h, $p, $s] = array_map(self::decode(...), $parts);
        if ($h === null || $p === null || $s === null || strlen($s) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return null;
        }
        $header = json_decode($h, true, 8);
        $claims = json_decode($p, true, 16);
        if (!is_array($header) || !is_array($claims) || ($header['alg'] ?? null) !== 'EdDSA' || isset($header['crit']) || !is_string($header['kid'] ?? null)) {
            return null;
        }
        $public = $keyFor($header['kid']);
        if ($public === null || strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || !sodium_crypto_sign_verify_detached($s, $parts[0] . '.' . $parts[1], $public)) {
            return null;
        }
        return [$header, $claims];
    }

    /** A random value that fits in an address or a header: $bytes of entropy. */
    public static function random(int $bytes = 32): string
    {
        return self::encode(random_bytes(max(16, $bytes)));
    }
}
