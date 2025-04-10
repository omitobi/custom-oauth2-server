<?php

declare(strict_types=1);

namespace Oauth2Server;

use DateInterval;
use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use Oauth2Server\Crypto\CloudCryptKey;
use Oauth2Server\Grant\OpenIdAuthCodeGrant;
use Oauth2Server\Repositories\TokenRepository;
use Oauth2Server\Repositories\AuthCodeRepository;
use Oauth2Server\Repositories\ClientRepository;
use Oauth2Server\Repositories\RefreshTokenRepository;
use Oauth2Server\Repositories\ScopeRepository;
use Oauth2Server\ResponseTypes\OpenIdBearerTokenResponse;
use Psr\Http\Message\ServerRequestInterface;

class OpenIdServerProvider extends ServiceProvider
{
    public function register(): void
    {
        $clientRepository = new ClientRepository();
        $accessTokenRepository = new TokenRepository();
        $idTokenRepository = new TokenRepository();
        $scopeRepository = new ScopeRepository();
//        $privateKey = storage_path('private.key');
        $privateKey = new CloudCryptKey('1');
        $responseType = new OpenIdBearerTokenResponse();

        $server = new OpenIdAuthorizationServer(
            clientRepository: $clientRepository,
            accessTokenRepository: $accessTokenRepository,
            idTokenTokenRepository: $idTokenRepository,
            scopeRepository: $scopeRepository,
            privateKey: $privateKey,
            encryptionKey: 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen',
            responseType: $responseType,
        );

        $authCodeRepository = new AuthCodeRepository();
        $refreshTokenRepository = new RefreshTokenRepository();
        // Enable the authentication code grant on the server with a token TTL of 1 hour
//        $server->enableGrantType(
//            new AuthCodeGrant(
//                $authCodeRepository,
//                $refreshTokenRepository,
//                new DateInterval('PT10M'),
//            ),
//            new DateInterval('PT1H')
//        );

        $server->enableGrantType(
            new OpenIdAuthCodeGrant(
                $authCodeRepository,
                $refreshTokenRepository,
                new DateInterval('PT10M'),
            ),
            new DateInterval('PT1H')
        );

        $this->app->instance(OpenIdAuthorizationServer::class, $server);



        $this->app->bind(ServerRequest::class, function ($app) {
//            return\Laminas\Diactoros\ServerRequestFactory::fromGlobals(
//                $_SERVER,
//                $_GET,
//                $_POST,
//                $_COOKIE,
//                $_FILES
//            );
            /** @var Request $laravelRequest */
            $laravelRequest = $app['request'];
            return new ServerRequest(
                serverParams: $laravelRequest->server->all(),
                uploadedFiles: $laravelRequest->files->all(),
                uri: $laravelRequest->url(),
                method: $laravelRequest->method(),
                headers: $laravelRequest->headers->all(),
                cookieParams: $laravelRequest->cookies->all(),
                queryParams: $laravelRequest->query->all(),
                parsedBody: $laravelRequest->request->all(),
            );
});


    }
}
