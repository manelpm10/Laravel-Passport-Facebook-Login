<?php

namespace Danjdewhurst\PassportFacebookLogin;

use App\User;
use Facebook\Facebook;
use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\OAuthServerException;

trait FacebookLoginTrait
{
    /**
     * @var string
     */
    protected $profilePicUrl = 'https://graph.facebook.com/{FACEBOOK_ID}/picture?type=large';

    /**
     * Logs a App\User in using a Facebook token via Passport
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Illuminate\Database\Eloquent\Model|null
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function loginFacebook(Request $request)
    {
        try {
            if ($request->get('fb_token')) {

                // Initialise Facebook SDK.
                $fb = new Facebook([
                    'app_id' => config('facebook.app.id'),
                    'app_secret' => config('facebook.app.secret'),
                    'default_graph_version' => 'v2.5',
                ]);
                $fb->setDefaultAccessToken($request->get('fb_token'));

                // Facebook request.
                $response = $fb->get('/me?locale=en_GB&fields=first_name,last_name,email');
                $fbUser = $response->getDecodedBody();

                if (empty($fbUser['email'])) {
                    throw new \Exception('Email access revoked', 400);
                }

                /** @var User $userModel */
                $userModel = config('auth.providers.users.model');

                $user = $userModel::where('email', $fbUser['email'])
                    ->orWhere('facebook_id', $fbUser['id'])
                    ->first();

                // Check if the user has already signed up.
                if (empty($user)) {
                    $fullName = $fbUser['first_name'];
                    if (!empty($fbUser['last_name'])) {
                        $fullName .= ' ' . $fbUser['last_name'];
                    }

                    $user = new $userModel();
                    $user->facebook_id = $fbUser['id'];
                    $user->name = $fullName;
                    $user->avatar = $this->buildProfilePictureUrl($fbUser['id']);
                    $user->email = $fbUser['email'];
                    $user->password = uniqid('fb_', true);
                    $user->language = $request->get('language', 'en');

                    $user->save();
                } elseif (empty($user->facebook_id)) {
                    // If user is signed up before via credentials, save the facebook id.
                    $user->facebook_id = $fbUser['id'];
                    $user->avatar = $this->buildProfilePictureUrl($fbUser['id']);

                    $user->save();
                }

                return $user;
            }
        } catch (\Exception $e) {
            throw OAuthServerException::accessDenied($e->getMessage());
        }

        return null;
    }

    /**
     * @param string $facebookId
     *
     * @return string
     */
    protected function buildProfilePictureUrl($facebookId)
    {
        return str_replace('{FACEBOOK_ID}', $facebookId, $this->profilePicUrl);
    }
}
