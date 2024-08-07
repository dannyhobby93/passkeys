<?php

namespace App\Http\Controllers;

use App\Models\Passkey;
use Illuminate\Http\Request;
use Webauthn\PublicKeyCredential;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Session;
use Webauthn\AuthenticatorAssertionResponse;
use Illuminate\Validation\ValidationException;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;

class PasskeyController extends Controller
{
    public function authenticate(Request $request)
    {
        $data = $request->validate(['answer' => 'required|json']);

        /** @var PublicKeyCredential $public_key_credential */
        $public_key_credential = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))
            ->create()
            ->deserialize($data['answer'], PublicKeyCredential::class, 'json');

        if (!$public_key_credential->response instanceof AuthenticatorAssertionResponse) {
            return to_route('profile.edit')->withFragment('managePasskeys');
        }

        $passkey = Passkey::firstWhere('credential_id', $public_key_credential->rawId);

        if (!$passkey) {
            throw ValidationException::withMessages(['answer' => 'This passkey is not valid.']);
        }

        try {
            $public_key_credential_source = AuthenticatorAssertionResponseValidator::create()->check(
                credentialId: $passkey->data,
                authenticatorAssertionResponse: $public_key_credential->response,
                publicKeyCredentialRequestOptions: Session::get('passkey-authentication-options'),
                request: $request->getHost(),
                userHandle: null,
            );
        } catch (\Throwable $e) {
            throw ValidationException::withMessages([
                'answer' => 'This passkey is not valid.'
            ]);
        }

        $passkey->update(['data' => $public_key_credential_source]);

        Auth::loginUsingId($passkey->user_id);
        $request->session()->regenerate();

        return to_route('dashboard');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $data = $request->validateWithBag('createPasskey', [
            'name' => 'required|string|min:3|max:255',
            'passkey' => 'required|json',
        ]);

        /** @var PublicKeyCredential $public_key_credential */
        $public_key_credential = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))
            ->create()
            ->deserialize($data['passkey'], PublicKeyCredential::class, 'json');

        if (!$public_key_credential->response instanceof AuthenticatorAttestationResponse) {
            return to_route('login');
        }

        try {
            $public_key_credential_source = AuthenticatorAttestationResponseValidator::create()->check(
                authenticatorAttestationResponse: $public_key_credential->response,
                publicKeyCredentialCreationOptions: Session::get('passkey-registration-options'),
                request: $request->getHost(),
            );
        } catch (\Throwable $e) {
            throw ValidationException::withMessages([
                'name' => 'This given passkey is invalid.'
            ])->errorBag('createPasskey');
        }

        $request->user()->passkeys()->create([
            'name' => $data['name'],
            'data' => $public_key_credential_source
        ]);

        return to_route('profile.edit')->withFragment('managePasskeys');
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Passkey $passkey)
    {
        Gate::authorize('delete', $passkey);

        $passkey->delete();

        return to_route('profile.edit')->withFragment('managePasskeys');
    }
}
