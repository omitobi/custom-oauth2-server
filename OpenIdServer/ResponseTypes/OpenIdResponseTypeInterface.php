<?php

namespace Oauth2Server\ResponseTypes;

use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Oauth2Server\Entities\IdTokenEntity;
use Oauth2Server\Entities\IdTokenEntityInterface;

interface OpenIdResponseTypeInterface extends ResponseTypeInterface
{
    public function setIdToken(IdTokenEntityInterface $idToken): void;
}
