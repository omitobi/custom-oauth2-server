<?php

namespace Oauth2Server\Crypto;

use App\Services\HSM\SignData;

interface CloudSignerProviderInterface
{
    public function sign(SignData $signData): string;

    public function verify(string $signature, SignData $signData);

    public function getPublicKey(mixed $key): string;
}
