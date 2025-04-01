<?php

use Illuminate\Support\Facades\Route;

Route::post('/access_token', [\Oauth2Server\Controllers\Oauth2Controller::class, 'accessToken']);
