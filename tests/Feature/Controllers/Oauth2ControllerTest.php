<?php

namespace Tests\Feature\Controllers;

use Tests\TestCase;

class Oauth2ControllerTest extends TestCase
{
    public function testCodeAuthorization(): string
    {
        $this->withoutExceptionHandling();

        $response = $this->request(
            method: 'get',
            path: '/authorize?'
            . 'client_id=myawesomeapp'
            . '&redirect_uri=http://examples.test'
            . '&response_type=code'
            . '&state=state'
            . '&scope=openid'
            ,
            responseType: 'redirection',
        );

        $this->assertStringContainsString(
            'code=',
            $response,
        );

        $this->assertStringContainsString(
            'state=state',
            $response,
        );

        return $response;
    }

    public function testAccessToken(): void
    {
        $this->withoutExceptionHandling();

        $codeResponse = $this->testCodeAuthorization();

        // Extract 'code' from query parameters.
        $parsedUrl = parse_url($codeResponse, PHP_URL_QUERY);

        parse_str($parsedUrl, $params);
        $code = $params['code'];

        $response = $this->request(method: 'post', path: '/api/access_token', data: [
            'grant_type' => 'authorization_code',
            'client_id' => 'myawesomeapp',
            'client_secret' => 'abc123',
            'redirect_uri' => 'http://examples.test',
            'code' => $code,
            'state' => 'state',
        ], headers: [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ]);

        $this->assertEquals('Bearer', $response['token_type']);
        $this->assertArrayHasKey('access_token', $response);
        $this->assertArrayHasKey('expires_in', $response);
        $this->assertArrayHasKey('refresh_token', $response);
        $this->assertArrayHasKey('id_token', $response);
    }

    /**
     * Make this a wrapper for the test http client call, so that we can move the test away from Laravel easily.
     */
    public function request(string $method, string $path, array $data = [], array $headers = [], string $responseType = 'json'): array|string
    {
        $requestParameters = [$path, $data, $headers];

        if ($method == 'get') {
            $requestParameters = [$path, $headers];
        }

        $response = $this->$method(...$requestParameters);

        return match ($responseType) {
            'redirection' => $response->headers->get('Location'),
            default => $response->json(),
        };
    }
}
