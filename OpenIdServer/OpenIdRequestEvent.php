<?php

declare(strict_types=1);

namespace Oauth2Server;

use League\OAuth2\Server\RequestEvent;

class OpenIdRequestEvent extends RequestEvent
{
    public const ID_TOKEN_ISSUED = 'id_token.issued';
}
