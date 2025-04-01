<?php

declare(strict_types=1);

namespace App\Services\HSM;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

class Local
{
    public function createJwt(array $data, string $algorithm = 'RS256'): string
    {
        return $this->build($data, $algorithm);
    }


    public function getJWK(): mixed
    {
        $key = JWKFactory::createFromKeyFile(
            file: Storage::path('hello/private_key.pem'), // The filename
            additional_values: [
                'use' => 'sig',
            ],
        );

        return tap($key->toPublic()->all(), fn($public) => $this->storePublic($public));
    }

    public function storePublic($key = null): void
    {
        $key = $key ?? $this->getJWK();

        Storage::put('hello/public_key_jwk.json', json_encode($key));
    }

    public function generateKeyPair(): void
    {
        $config = array(
            "digest_alg" => "sha512",
            "private_key_bits" => 4096,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );

// Create the private and public key
        $res = openssl_pkey_new($config);

        /* Extract the private key from $res to $privKey */
        openssl_pkey_export($res, $privKey);

        /* Extract the public key from $res to $pubKey */
        $pubKey = openssl_pkey_get_details($res);
        $pubKey = $pubKey["key"];

        Storage::put('hello/private_key.pem', $privKey);
        Storage::put('hello/public_key.pem', $pubKey);
    }

    public function verify(string $token, string $algorithm = 'RS256'): bool
    {
        // The algorithm manager with the HS256 algorithm.
        $algorithmManager = new AlgorithmManager([
            new RS256(),
        ]);

// We instantiate our JWS Verifier.
        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );

        // Our key.
        $jwk = new JWK(Storage::json('hello/public_key_jwk.json'));

// The serializer manager. We only use the JWS Compact Serialization Mode.
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);

// The input we want to check

// We try to load the token.
        $jws = $serializerManager->unserialize($token);

// We verify the signature. This method does NOT check the header.
// The arguments are:
// - The JWS object,
// - The key,
// - The index of the signature to check. See
        $isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);

        $headerCheckerManager = new HeaderCheckerManager(
            [
                new AlgorithmChecker([$algorithm]),
                // We want to verify that the header "alg" (algorithm)
                // is present and contains "HS256"
            ],
            [
                new JWSTokenSupport(), // Adds JWS token type support
            ]
        );


        $headerCheckerManager->check($jws, 0);

        return $isVerified;
    }

    private function build(array $data, string $algorithm): string
    {
        $algorithmManager = new AlgorithmManager([
            new RS256(),
        ]);

        // Our key.
        $jwk = JWKFactory::createFromKeyFile(Storage::path('hello/private_key.pem'));

        // We instantiate our JWS Builder.
        $jwsBuilder = new JWSBuilder($algorithmManager);

        // The payload we want to sign. The payload MUST be a string hence we use our JSON Converter.
        $payload = json_encode($data);

        $jws = $jwsBuilder
            ->create()                               // We want to create a new JWS
            ->withPayload($payload)                  // We set the payload
            ->addSignature($jwk, [
                'alg' => 'RS256',
                'kid' => 'RP9T_2fhsIRqk2FT-14aVdE1p2Y',
            ]) // We add a signature with a simple protected header
            ->build();

        $serializer = new CompactSerializer(); // The serializer

        $token = $serializer->serialize($jws, 0);

        Log::info('This token is: ' . $token);

        return $token;
    }
}
