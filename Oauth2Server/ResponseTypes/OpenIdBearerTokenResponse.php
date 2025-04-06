<?php

namespace Oauth2Server\ResponseTypes;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use Oauth2Server\Entities\IdTokenEntityInterface;

class OpenIdBearerTokenResponse extends BearerTokenResponse implements OpenIdResponseTypeInterface
{
    private IdTokenEntityInterface $idToken;

    public function setIdToken(IdTokenEntityInterface $idToken): void
    {
        $this->idToken = $idToken;
    }

    public function getIdToken(): IdTokenEntityInterface
    {
        return $this->idToken;
    }

    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        return [
            'id_token' => $this->idToken->toString(),
        ];
    }
}
