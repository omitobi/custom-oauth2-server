<?php

namespace App\Services\HSM;

use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Storage;

final class Core
{
    /**
     * Supports only RSA256 (SHA256) signature
     */
    public function sign(string $keyId, string $data, string|int $algo = OPENSSL_ALGO_SHA256): ?string
    {
        $signature = null;

        openssl_sign($data, $signature, $this->getPrivateKey($keyId), $algo);

        return $signature;
    }

    public function verify(string $keyId, string $data, string $cypherText, string|int $algo = OPENSSL_ALGO_SHA256): bool
    {
        $public = openssl_get_publickey($this->getPublicKey($keyId));

        if ($public === false) {
            throw new \RuntimeException('Failed to get public key');
        }

        return openssl_verify($data, $cypherText, $public, $algo) == 1;
    }

    private function getPrivateKey(string $keyId): string
    {
        return Storage::get('private.key');
    }

    public function getPublicKey(string $keyId): string
    {
        return Storage::get('public.key');
    }

    public function encrypt(
        string $keyId,
        string $algo,
        string $data,
    ): string {
        $algorithm = $this->algo($algo);

        return $this->getEncrypter($keyId, $algorithm)
            ->encrypt($data);
    }

    public function decrypt(
        string $keyId,
        string $algo,
        string $data,
    ): string {
        $algorithm = $this->algo($algo);

        $decrypted = $this->getEncrypter($keyId, $algorithm)
            ->decrypt($data);

        return explode('-', $decrypted)[2];
    }

    public function authenticate(
        string $userId,
        string $verificationKey
    ) {
      // todo.implement.
    }

    private function algo(string $algo): string
    {
        return [
            'SHA-256' => 'aes-256-gcm',
        ][$algo];
    }

    private function getEncrypter(string $keyId, string $cypher): \Illuminate\Contracts\Encryption\Encrypter
    {
        $key = [
            // The keys should never be known.
            '1' => '12345678901234567890123456789012',
            '2' => '02345678901234567890123456789012',
        ][$keyId];

        return new Encrypter($key, $cypher);
    }
}
