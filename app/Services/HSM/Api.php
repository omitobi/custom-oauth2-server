<?php

declare(strict_types=1);

namespace App\Services\HSM;

final class Api
{
    private Core $core;

    public function __construct()
    {
        $this->core = new Core();
    }

    public function encrypt(SignData $signData): string
    {
        return $this->core->encrypt(
            keyId: $signData->keyId,
            algo: $signData->hashAlgo,
            data: $signData->payload,
        );
    }


    public function decrypt(SignData $signData): string
    {
        return $this->core->decrypt(
            $signData->keyId,
            $signData->hashAlgo,
            $signData->payload,
        );
    }

    public function sign(SignData $signData): string
    {
        return $this->core->sign(
            keyId: $signData->keyId,
            data: $signData->payload,
//            algo: $signData->hashAlgo,
        );
    }

    public function verify(SignData $signData, string $signature): bool
    {
        return $this->core->verify(
            keyId: $signData->keyId,
            data: $signData->payload,
            cypherText: $signature,
//            algo: $signData->hashAlgo,
        );
    }

    public function publicKey(string $keyId): string
    {
        return $this->core->getPublicKey($keyId);
    }
}
