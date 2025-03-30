<?php

declare(strict_types=1);

namespace Oauth2Server\Controllers;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Stream;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Oauth2Server\Entities\UserEntity;
use Oauth2Server\Oauth2ServiceServer;
use Psr\Http\Message\ResponseInterface;

class Oauth2Controller
{
    public function __construct(protected AuthorizationServer $server)
    {
    }

    public function authorize(AuthorizationServer $server, ServerRequest $psrRequest, Response $psrResponse): ResponseInterface
    {
        try {
            // Validate the HTTP request and return an AuthorizationRequest object.
            // The auth request object can be serialized into a user's session
            $authRequest = $server->validateAuthorizationRequest($psrRequest);

            // Once the user has logged in set the user on the AuthorizationRequest
            $authRequest->setUser(new UserEntity());

            // Once the user has approved or denied the client update the status
            // (true = approved, false = denied)
            $authRequest->setAuthorizationApproved(true);

            // Return the HTTP redirect response
            return $server->completeAuthorizationRequest($authRequest, $psrResponse);
        } catch (OAuthServerException $exception) {
            return $exception->generateHttpResponse($psrResponse);
        } catch (Exception $exception) {
            $body = new Stream('php://temp', 'r+');
            $body->write($exception->getMessage());

            return $psrResponse->withStatus(500)->withBody($body);
        }
    }
}
