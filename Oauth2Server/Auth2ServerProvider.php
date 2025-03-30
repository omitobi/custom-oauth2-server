<?php

declare(strict_types=1);

namespace Oauth2Server;

use DateInterval;
use Illuminate\Support\ServiceProvider;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use Oauth2Server\Repositories\AccessTokenRepository;
use Oauth2Server\Repositories\AuthCodeRepository;
use Oauth2Server\Repositories\ClientRepository;
use Oauth2Server\Repositories\RefreshTokenRepository;
use Oauth2Server\Repositories\ScopeRepository;
use Psr\Http\Message\ServerRequestInterface;

class Auth2ServerProvider extends ServiceProvider
{
    public function register(): void
    {
        $clientRepository = new ClientRepository();
        $accessTokenRepository = new AccessTokenRepository();
        $scopeRepository = new ScopeRepository();
        $privateKey = storage_path('private.key');
        $responseType = new BearerTokenResponse();

        $server = new AuthorizationServer(
            clientRepository: $clientRepository,
            accessTokenRepository: $accessTokenRepository,
            scopeRepository: $scopeRepository,
            privateKey: $privateKey,
            encryptionKey: 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen',
            responseType: $responseType,
        );

        $authCodeRepository = new AuthCodeRepository();
        $refreshTokenRepository = new RefreshTokenRepository();
        // Enable the authentication code grant on the server with a token TTL of 1 hour
        $server->enableGrantType(
            new AuthCodeGrant(
                $authCodeRepository,
                $refreshTokenRepository,
                new DateInterval('PT10M'),
            ),
            new DateInterval('PT1H')
        );

        $this->app->instance(AuthorizationServer::class, $server);

        $request = \Laminas\Diactoros\ServerRequestFactory::fromGlobals(
            $_SERVER,
            $_GET,
            $_POST,
            $_COOKIE,
            $_FILES
        );

        $this->app->instance(ServerRequest::class, $request);
    }
}
