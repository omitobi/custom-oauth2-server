<?php

namespace Oauth2Server\Grant;

use DateInterval;
use InvalidArgumentException;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestRefreshTokenEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

class OpenIDAuthCodeGrant extends AuthCodeGrant implements GrantTypeInterface
{
    /**
     * @param ServerRequestInterface $request
     * @return AuthorizationRequestInterface
     * @throws OAuthServerException
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $authorizationRequest = parent::validateAuthorizationRequest($request);

        $this->validateOpenIdScope(
            $this->getQueryStringParameter('scope', $request),
        );

        $this->validateOpenIdRedirectUri($request);

        return $authorizationRequest;
    }

    /**
     * @param ServerRequestInterface $request
     * @return void
     * @throws OAuthServerException
     */
    protected function validateOpenIdRedirectUri(ServerRequestInterface $request): void
    {
        $clientId = $this->getQueryStringParameter(
            'client_id',
            $request,
            $this->getServerParameter('PHP_AUTH_USER', $request)
        );

        $client = $this->getClientEntityOrFail($clientId, $request);
        $redirectUri = $this->getQueryStringParameter('redirect_uri', $request) ?? '';

        parent::validateRedirectUri($redirectUri, $client, $request);
    }

    private function validateOpenIdScope(string|array|null $scopes): void
    {
        if ($scopes === null) {
            $scopes = [];
        } elseif (is_string($scopes)) {
            $scopes = $this->convertScopesQueryStringToArray($scopes);
        }

        if (!in_array('openid', $scopes, true)) {
            throw OAuthServerException::invalidRequest('scope', '\'openid\' scope is missing in request parameters.');
        }
    }

    private function convertScopesQueryStringToArray(string $scopes): array
    {
        return array_filter(explode(self::SCOPE_DELIMITER_STRING, trim($scopes)), static fn ($scope) => $scope !== '');
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        $client = $this->validateClient($request);

        $encryptedAuthCode = $this->getRequestParameter('code', $request);

        if ($encryptedAuthCode === null) {
            throw OAuthServerException::invalidRequest('code');
        }

        try {
            $authCodePayload = json_decode($this->decrypt($encryptedAuthCode));

            $this->validateAuthorizationCode($authCodePayload, $client, $request);

            $scopes = $this->scopeRepository->finalizeScopes(
                $this->validateScopes($authCodePayload->scopes),
                $this->getIdentifier(),
                $client,
                $authCodePayload->user_id,
                $authCodePayload->auth_code_id
            );
        } catch (InvalidArgumentException $e) {
            throw OAuthServerException::invalidGrant('Cannot validate the provided authorization code');
        } catch (LogicException $e) {
            throw OAuthServerException::invalidRequest('code', 'Issue decrypting the authorization code', $e);
        }

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $authCodePayload->user_id, $scopes);
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));
        $responseType->setAccessToken($accessToken);

        // Issue and persist new refresh token if given
        $refreshToken = $this->issueRefreshToken($accessToken);

        if ($refreshToken !== null) {
            $this->getEmitter()->emit(new RequestRefreshTokenEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request, $refreshToken));
            $responseType->setRefreshToken($refreshToken);
        }

        // Revoke used auth code
        $this->authCodeRepository->revokeAuthCode($authCodePayload->auth_code_id);

        return $responseType;
    }

    private function validateAuthorizationCode(
        \stdClass $authCodePayload,
        ClientEntityInterface $client,
        ServerRequestInterface $request
    ): void {
        if (!property_exists($authCodePayload, 'auth_code_id')) {
            throw OAuthServerException::invalidRequest('code', 'Authorization code malformed');
        }

        if (time() > $authCodePayload->expire_time) {
            throw OAuthServerException::invalidGrant('Authorization code has expired');
        }

        if ($this->authCodeRepository->isAuthCodeRevoked($authCodePayload->auth_code_id) === true) {
            throw OAuthServerException::invalidGrant('Authorization code has been revoked');
        }

        if ($authCodePayload->client_id !== $client->getIdentifier()) {
            throw OAuthServerException::invalidRequest('code', 'Authorization code was not issued to this client');
        }

        // The redirect URI is required in this request if it was specified
        // in the authorization request
        $redirectUri = $this->getRequestParameter('redirect_uri', $request);
        if ($authCodePayload->redirect_uri === null) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }

        // If a redirect URI has been provided ensure it matches the stored redirect URI
        if ($authCodePayload->redirect_uri !== $redirectUri) {
            throw OAuthServerException::invalidRequest('redirect_uri', 'Invalid redirect URI');
        }

        if (!$authCodePayload->scopes) {
            throw OAuthServerException::invalidRequest('scope', 'At least \'openid\' scope must be provided');
        }

        if (!in_array('openid', $authCodePayload->scopes, true)) {
            throw OAuthServerException::invalidRequest('scope', '\'openid\' scope always required');
        }
    }

    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
    {
        $responseTye = $request->getQueryParams()['response_type'] ?? null;
        if ($responseTye !== 'code') {
            return false;
        }
        $clientId = $request->getQueryParams()['client_id'] ?? null;

        if (empty($clientId)) {
            return false;
        }

        // Check for redirect_uri.

        $redirectUri = $request->getQueryParams()['redirect_uri'] ?? null;

        if (empty($redirectUri)) {
            return false;
        }

        // Check for openid scope.
        $scope = $request->getQueryParams()['scope'] ?? '';
        $scopes = explode(self::SCOPE_DELIMITER_STRING, $scope);

        if (!in_array('openid', $scopes, true)) {
            return false;
        }

        return true;
    }

    public function getIdentifier(): string
    {
        return 'authorization_code';
    }
}
