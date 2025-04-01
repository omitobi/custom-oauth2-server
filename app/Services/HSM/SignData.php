<?php

namespace App\Services\HSM;

final readonly class SignData
{
    public function __construct(
        public string $keyId,
        public string $payload,
        public string $hashAlgo = 'SHA-256'
    ) {
    }
}
