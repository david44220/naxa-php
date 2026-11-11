<?php

declare(strict_types=1);

namespace Naxa\Sdk;

use Naxa\Sdk\Exception\ConfigurationError;
use Naxa\Sdk\Internal\Jose;

/**
 * An Ed25519 key pair of the application. An application holds two:
 *
 * - the key of its **client assertions**, whose public half is written in the application's
 *   record in the developer console: it is how Naxa knows the application;
 * - the key of its **proofs of possession** (DPoP), which Naxa learns from the proofs
 *   themselves: every token is bound to it and is worth nothing without it.
 *
 * The secret half never leaves the application's server: keep it where the server keeps its
 * secrets, never in the code, a browser or a mobile application.
 */
final class Key
{
    private function __construct(#[\SensitiveParameter] private readonly string $secret)
    {
    }

    public static function generate(): self
    {
        return new self(sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair()));
    }

    /** From what export() gave (the 64 bytes of the secret key, base64); a 32-byte seed is accepted too. */
    public static function fromSecret(#[\SensitiveParameter] string $encoded): self
    {
        $raw = base64_decode(strtr(trim($encoded), '-_', '+/'), true);
        if ($raw !== false && strlen($raw) === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            $raw = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($raw));
        }
        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new ConfigurationError('A key must be a base64 Ed25519 secret key (64 bytes), as Key::export() writes it.');
        }
        return new self($raw);
    }

    /** The secret half, base64: what the server stores among its secrets. */
    public function export(): string
    {
        return base64_encode($this->secret);
    }

    /** The public half, base64: what the developer console asks for. */
    public function publicKey(): string
    {
        return base64_encode($this->rawPublicKey());
    }

    /** @return array{kty:string, crv:string, x:string} the public half as a JWK (RFC 8037) */
    public function jwk(): array
    {
        return ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Jose::encode($this->rawPublicKey())];
    }

    /** The thumbprint of the public half (RFC 7638): what Naxa binds a token to (`jkt`). */
    public function thumbprint(): string
    {
        return Jose::encode(hash('sha256', '{"crv":"Ed25519","kty":"OKP","x":"' . Jose::encode($this->rawPublicKey()) . '"}', true));
    }

    /** @return string the 64 bytes of the signature */
    public function sign(string $message): string
    {
        return sodium_crypto_sign_detached($message, $this->secret);
    }

    private function rawPublicKey(): string
    {
        return sodium_crypto_sign_publickey_from_secretkey($this->secret);
    }

    /** A dump or a log shows which key it is, never the key. */
    public function __debugInfo(): array
    {
        return ['public_key' => $this->publicKey()];
    }

    public function __serialize(): array
    {
        throw new \LogicException('A key is not serialized: store Key::export() among the secrets of the server.');
    }
}
