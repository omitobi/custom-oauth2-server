<?php

use Illuminate\Support\Facades\Route;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Stream;
use League\OAuth2\Server\Exception\OAuthServerException;
use Oauth2Server\Entities\UserEntity;
use Oauth2Server\Oauth2ServiceServer;
use Psr\Http\Message\ResponseInterface;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/authorize', [\Oauth2Server\Controllers\Oauth2Controller    ::class, 'authorize']);
