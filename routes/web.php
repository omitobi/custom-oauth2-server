<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/authorize', [\Oauth2Server\Controllers\Oauth2Controller::class, 'authorize']);
