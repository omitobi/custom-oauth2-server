<?php

namespace Oauth2Server\RequestTypes;

use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;

interface OpenIdAuthorizationRequestInterface extends AuthorizationRequestInterface
{
    public function setNonce(string|null $nonce): void;

    public function getNonce(): string|null;
}
