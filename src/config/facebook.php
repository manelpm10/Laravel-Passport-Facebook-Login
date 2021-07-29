<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Application
    |--------------------------------------------------------------------------
    |
    | The facebook ID, secret from the developer's page and the DateInterval format.
    | See https://www.php.net/manual/es/dateinterval.format.php for mor info about format
    |
    */

    'app' => [
        'id' => env('FACEBOOK_APP_ID'),
        'secret' => env('FACEBOOK_APP_SECRET'),
        'token_expire_interval' => env('TOKEN_EXPIRE_INTERVAL', 'P1D'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Registration Fields
    |--------------------------------------------------------------------------
    |
    | The name of the fields on the user model that need to be updated,
    | if null, they shall not be updated. (valid for name, first_name, last_name)
    |
    */

    'registration' => [
        'facebook_id' => env('FACEBOOK_ID_COLUMN', 'facebook_id'),
        'email'       => env('EMAIL_COLUMN', 'email'),
        'password'    => env('PASSWORD_COLUMN', 'password'),
        'first_name'  => env('FIRST_NAME_COLUMN', 'first_name'),
        'last_name'   => env('LAST_NAME_COLUMN', 'last_name'),
        'name'        => env('NAME_COLUMN', 'name'),
        'attach_role' => env('ATTACH_ROLE', null),
    ],
];
