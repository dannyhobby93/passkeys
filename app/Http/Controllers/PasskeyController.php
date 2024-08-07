<?php

namespace App\Http\Controllers;

use App\Models\Passkey;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;

class PasskeyController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $data = $request->validate([
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
            'credential_id' => $public_key_credential_source->publicKeyCredentialId,
            'data' => $public_key_credential_source
        ]);

        return to_route('profile.edit')->withFragment('managePasskeys');
    }

    /**
     * Display the specified resource.
     */
    public function show(Passkey $passkey)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(Passkey $passkey)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, Passkey $passkey)
    {
        //
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
