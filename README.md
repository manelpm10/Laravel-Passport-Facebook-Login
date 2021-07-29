# Laravel Passport Facebook Login
Provides a new Laravel Passport Grant Client named `facebook_login`, allowing you to log a user in with just their Facebook Login token.

A new user will be created (and optionally assigned to an role - `$user->attachRole(ID)`) if the email address doesn't exist.

## Installation:
Install with composer `composer require manelpm10/laravel-passport-facebook-login`

### Versions:
* Laravel 5.5 and Passport 4.0 only supported at this time

## Dependencies:
* `"laravel/passport": "^4.0"`
* `"facebook/graph-sdk": "^5.6"`

## Setup:
* ***Using Laravel 5.4 or below?*** add `Danjdewhurst\PassportFacebookLogin\FacebookLoginGrantProvider::class` to your list of providers **after** `Laravel\Passport\PassportServiceProvider`. Laravel 5.5 uses auto-discovery, so manual service registration is no longer required.
* Add `Danjdewhurst\PassportFacebookLogin\FacebookLoginTrait` Trait to your `User` model (or whatever model you have configured to work with Passport).
* Run `php artisan vendor:publish`, this will create a `config/facebook.php` file.
* Enter your Facebook App details in your `.env` file: `FACEBOOK_APP_ID` and `FACEBOOK_APP_SECRET`.
* Optional: To automatically attach a role (https://github.com/Zizaco/entrust) to new users, use the 'ATTACH_ROLE' env setting.

**Config:**
```php
    /*
    |--------------------------------------------------------------------------
    | Application
    |--------------------------------------------------------------------------
    |
    | The facebook ID, secret from the developer's page and the DateInterval format for expire token ttl.
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
```

## How To Use:

* Make a **POST** request to `https://your-site.com/oauth/token`.
* The POST body should contain
    1. `grant_type` = `facebook_login`
    2. `fb_token` = `{token from facebook login}`.
    3. client_id
    4. client_secret
* An `access_token` and `refresh_token` will be returned if successful.

## Assumptions:
* Your `User` model has the folowing fields:
* * `facebook_id`
* * `name` or `first_name` & `last_name`
* * `email`
* * `password`

## Credits:
* https://github.com/mirkco/Laravel-Passport-Facebook-Login
* https://github.com/mikemclin/passport-custom-request-grant
