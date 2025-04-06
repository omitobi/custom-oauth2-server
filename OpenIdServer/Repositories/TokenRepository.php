<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace Oauth2Server\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Oauth2Server\Entities\AccessTokenEntity;
use Oauth2Server\Entities\IdTokenEntity;
use Oauth2Server\Entities\IdTokenEntityInterface;

class TokenRepository implements IdTokenRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        // Some logic here to save the access token to a database
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken($tokenId): void
    {
        // Some logic here to revoke the access token
    }

    /**
     * {@inheritdoc}
     */
    public function isAccessTokenRevoked($tokenId): bool
    {
        return false; // Access token hasn't been revoked
    }

    /**
     * {@inheritdoc}
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null): AccessTokenEntityInterface
    {
        $accessToken = new AccessTokenEntity();

        $accessToken->setClient($clientEntity);

        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        if ($userIdentifier !== null) {
            $accessToken->setUserIdentifier((string) $userIdentifier);
        }

        return $accessToken;
    }

    public function getNewIdToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null): IdTokenEntityInterface
    {
        $idToken = new IdTokenEntity();

        $idToken->setClient($clientEntity);

        $idToken->setIssuer(url('/'));

        foreach ($scopes as $scope) {
            $idToken->addScope($scope);
        }

        if ($userIdentifier !== null) {
            $idToken->setUserIdentifier((string) $userIdentifier);
        }

        return $idToken;
    }
}
