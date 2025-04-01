<?php

namespace Oauth2Server\Crypto;

use League\OAuth2\Server\CryptKeyInterface;

class CloudCryptKey implements CryptKeyInterface
{
    public function __construct(public readonly string $keyId)
    {
    }

    public function getKeyPath(): string
    {
        // No path necessary for Cloud based Key.
        return '';
    }

    public function getPassPhrase(): ?string
    {
        // No pass phrase necessary for Cloud based key.
        return null;
    }

    public function getKeyContents(): string
    {
        return $this->keyId;
    }
}
