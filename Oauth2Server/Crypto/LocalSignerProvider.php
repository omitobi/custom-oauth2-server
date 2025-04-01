<?php

namespace Oauth2Server\Crypto;

use App\Services\HSM\Api;
use App\Services\HSM\SignData;

class LocalSignerProvider implements CloudSignerProviderInterface
{
    public function sign(SignData $signData): string
    {
        $api = new Api();
        $signature = $api->sign($signData);

        return base64_encode($signature);
    }

    public function verify(string $signature, SignData $signData): bool
    {
        $api = new Api();

        return $api->verify($signData, $signature);
    }

    public function getPublicKey(mixed $key): string
    {
        $api = new Api();

        return $api->publicKey($key);
    }
}
