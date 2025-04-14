<?php

declare(strict_types=1);

namespace Oauth2Server;

use DateInterval;
use Defuse\Crypto\Key;
use Lcobucci\JWT\Signer;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Oauth2Server\Grant\OpenIdGrantTypeInterface;
use Oauth2Server\Repositories\IdTokenRepositoryInterface;
use Oauth2Server\Servers\AuthorizationServerInterface;

class OpenIdAuthorizationServer extends AuthorizationServer implements AuthorizationServerInterface
{
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        protected IdTokenRepositoryInterface $idTokenTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        CryptKeyInterface|string $privateKey,
        Key|string $encryptionKey,
        ?ResponseTypeInterface $responseType = null,
        protected Signer|null $signer = null,
    ) {
        parent::__construct($clientRepository, $accessTokenRepository, $scopeRepository, $privateKey, $encryptionKey, $responseType);
    }

    public function enableGrantType(OpenIdGrantTypeInterface|GrantTypeInterface $grantType, ?DateInterval $accessTokenTTL = null): void
    {
        $grantType->setIdTokenRepository($this->idTokenTokenRepository);
        parent::enableGrantType($grantType, $accessTokenTTL);
    }
}
