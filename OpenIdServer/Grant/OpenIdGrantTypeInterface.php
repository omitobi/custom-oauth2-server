<?php

namespace Oauth2Server\Grant;

use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Oauth2Server\Repositories\IdTokenRepositoryInterface;

interface OpenIdGrantTypeInterface extends GrantTypeInterface
{
    public function setIdTokenRepository(IdTokenRepositoryInterface $idTokenRepository): void;
}
