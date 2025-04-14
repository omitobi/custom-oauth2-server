<?php

namespace Oauth2Server\Servers;

use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationServerInterface
{
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface;

    public function completeAuthorizationRequest(
        AuthorizationRequestInterface $authRequest,
        ResponseInterface $response
    ): ResponseInterface;

    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface;
}
