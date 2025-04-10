<?php

namespace Oauth2Server\Crypto;

use App\Services\HSM\SignData;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

class CloudSigner implements Signer
{
    public function __construct(protected CloudSignerProviderInterface $provider)
    {
    }

    public function algorithmId(): string
    {
//        return 'SHA-256';
        return 'RS256';
    }

    public function sign(string $payload, Key $key): string
    {
        $signData = new SignData(
            keyId: $key->contents(),
            payload: $payload,
            hashAlgo: $this->algorithmId(),
        );

        return $this->provider->sign($signData);
    }

    /**
     * @param string $expected - Same as the signature to verify
     * @param string $payload - the original content of the data to verify against.
     */
    public function verify(string $expected, string $payload, Key $key): bool
    {
        $signData = new SignData(
            keyId: $key->contents(),
            payload: $payload,
            hashAlgo: $this->algorithmId(),
        );

        return $this->provider->verify($expected, $signData);
    }

    public function getPublicKey(string $keyId): string
    {
        return $this->provider->getPublicKey($keyId);
    }
}
