<?php

namespace CamIE\SuperApp;

use Exception;

class SuperApp_Token_Protocol {

    private string $superAppDomain;

    public function __construct(string $superAppDomain) {
        $this->superAppDomain = rtrim($superAppDomain, '/');
    }

    // =====================================================================
    // 4. JWT GENERATOR (Standard 3-Part Token)
    // =====================================================================
    public function signToken(
        array $payloadData,
        string $privateKeyPem,
        string $keyId = 'key_v1_79715956'
    ): string {
        $header = ['alg' => 'ES384', 'typ' => 'JWT', 'kid' => $keyId];
        $base64Header = SignVerifyUtils::base64UrlEncode(json_encode($header, JSON_UNESCAPED_SLASHES));

        $envelope = array_merge($payloadData, [
            'scope' => ["partner-supper-app"],
            'jti' => SignVerifyUtils::generateUuidV4(),
            'iat' => time()
        ]);
        
        $base64Payload = SignVerifyUtils::base64UrlEncode(json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        $stringToSign = "{$base64Header}.{$base64Payload}";
        
        $utils = new SignVerifyUtils($this->superAppDomain);
        $signature = $utils->generateSignature($stringToSign, $privateKeyPem);
        
        return "{$stringToSign}.{$signature}";
    }

    public function inspectToken(string $jwtString): void {
        $parts = explode('.', $jwtString);
        if (count($parts) !== 3) throw new Exception("Invalid JWT format.");

        $headerJson = SignVerifyUtils::base64UrlDecode($parts[0]);
        $payloadJson = SignVerifyUtils::base64UrlDecode($parts[1]);

        echo "Token Header:\n";
        print_r(json_decode($headerJson, true));
        echo "\nToken Payload:\n";
        print_r(json_decode($payloadJson, true));
    }

    // =====================================================================
    // 5. JWT VERIFIER
    // =====================================================================
    public function verifyAndExtractToken(string $jwtString): array {
        $parts = explode('.', $jwtString);
        if (count($parts) !== 3) throw new Exception("Invalid JWT format.");

        $base64Header = $parts[0];
        $base64Payload = $parts[1];
        $base64Signature = $parts[2];

        $header = json_decode(SignVerifyUtils::base64UrlDecode($base64Header), true);
        $envelope = json_decode(SignVerifyUtils::base64UrlDecode($base64Payload), true);
        
        $keyId = $header['kid'] ?? null;
        $senderUuid = $envelope['issby'] ?? null;

        if (!$senderUuid || !$keyId) {
            throw new Exception("Missing 'issby' in payload or 'kid' in header.");
        }

        $iat = $envelope['iat'] ?? null;
        if (!$iat) throw new Exception("Missing 'iat' (Issued At) claim.");

        $currentTimeInSeconds = time();
        if ($iat > $currentTimeInSeconds + SignVerifyUtils::CLOCK_SKEW_TOLERANCE) {
            throw new Exception("Token 'iat' ({$iat}) is in the future. Check server clocks.");
        }
        if ($currentTimeInSeconds - $iat > SignVerifyUtils::MAX_TOKEN_AGE_SECONDS) {
            throw new Exception("Token has expired. Possible replay attack.");
        }

        $utils = new SignVerifyUtils($this->superAppDomain);
        $publicKeyPem = $utils->fetchPublicKey($senderUuid, $keyId);

        $rawSignature = SignVerifyUtils::base64UrlDecode($base64Signature);
        $isValid = openssl_verify("{$base64Header}.{$base64Payload}", $rawSignature, $publicKeyPem, OPENSSL_ALGO_SHA384);

        if ($isValid !== 1) {
            throw new Exception("CRITICAL: Signature verification failed. Data tampered with or invalid key.");
        }
        
        return $envelope;
    }
}