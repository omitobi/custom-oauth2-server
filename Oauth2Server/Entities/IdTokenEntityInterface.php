<?php

namespace Oauth2Server\Entities;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

interface IdTokenEntityInterface extends AccessTokenEntityInterface
{
    public function setIssuer(string $issuer): void;
}
