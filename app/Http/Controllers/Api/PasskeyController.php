<?php

namespace App\Http\Controllers\Api;

use App\Models\Passkey;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Session;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialCreationOptions;

class PasskeyController extends Controller
{
    public function registerOptions(Request $request)
    {
        $request->validate([
            'name' => 'required|string|min:3|max:255'
        ]);

        $options = new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(
                name: config('app.name'),
                id: parse_url(config('app.url'), PHP_URL_HOST)
            ),
            user: new PublicKeyCredentialUserEntity(
                name: $request->user()->email,
                id: $request->user()->id,
                displayName: $request->user()->name
            ),
            challenge: Str::random(),
        );

        Session::flash('passkey-registration-options', $options);

        return $options;
    }

    public function authenticateOptions(Request $request)
    {
        $allowed_credentials = $request->filled('email') ?
            Passkey::whereRelation('user', 'email', $request->email)
                ->get()
                ->map(fn(Passkey $passkey) => $passkey->data)
                ->map(fn(PublicKeyCredentialSource $pkcs) => $pkcs->getPublicKeyCredentialDescriptor())
                ->all() : [];

        $options = new PublicKeyCredentialRequestOptions(
            challenge: Str::random(),
            rpId: parse_url(config('app.url'), PHP_URL_HOST),
            allowCredentials: $allowed_credentials
        );

        Session::flash('passkey-authentication-options', $options);

        return $options;
    }
}
