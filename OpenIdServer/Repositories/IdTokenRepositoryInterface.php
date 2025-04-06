<?php

namespace Oauth2Server\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Oauth2Server\Entities\IdTokenEntityInterface;

interface IdTokenRepositoryInterface extends AccessTokenRepositoryInterface
{
    public function getNewIdToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null): IdTokenEntityInterface;
}
