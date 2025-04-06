<?php

namespace Oauth2Server\RequestTypes;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

class OpenIdAuthorizationRequest extends AuthorizationRequest implements OpenIdAuthorizationRequestInterface
{
    private string|null $nonce;

    public function setNonce(string|null $nonce): void
    {
        $this->nonce = $nonce;
    }

    public function getNonce(): string|null
    {
        return $this->nonce;
    }
}
