<?php

namespace CamIE\SuperApp;

use Exception;

class TicketType {
    public const MINIAPP_REQUEST = 'MINIAPP_REQUEST';
    public const MINIAPP_RESPONSE = 'MINIAPP_RESPONSE';
}

class SuperApp_Ticket_Protocol {

    private string $superAppDomain;

    public function __construct(string $superAppDomain) {
        $this->superAppDomain = rtrim($superAppDomain, '/');
    }

    // =====================================================================
    // 1. THE SENDER (Custom Routing Ticket)
    // =====================================================================
    public function createTicket(
        string $ticketType,
        array $businessData,
        string $privateKeyPem,
        string $issuer,
        string $audience,
        string $kid = "key_v1_79715956"
    ): string {
        $coreData = array_merge($businessData, [
            'nonce' => SignVerifyUtils::generateUuidV4(),
            'iat' => time(),
        ]);

        $coreDataString = json_encode($coreData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $checksum = hash('sha256', $coreDataString);

        $envelope = [
            'data' => $coreData,
            'checksum' => $checksum,
            'issby' => $issuer,
            'aud' => $audience,
            'kid' => $kid
        ];

        $base64Payload = SignVerifyUtils::base64UrlEncode(json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        $utils = new SignVerifyUtils($this->superAppDomain);
        $signature = $utils->generateSignature($base64Payload, $privateKeyPem);

        $signedTicket = [
            'type' => $ticketType,
            'version' => "v1",
            'alg' => "ES384",
            'hash_alg' => "SHA-256",
            'signature' => "{$base64Payload}.{$signature}"
        ];

        return TicketEncoder::encodeToBase64($signedTicket);
    }

    public function inspectTicket(string $base64String): void {
        $myTicket = TicketEncoder::decodeFromBase64($base64String);
        $parts = explode('.', $myTicket['signature'] ?? '');
        if (count($parts) !== 2) throw new Exception("Invalid JWS format");

        $jsonString = SignVerifyUtils::base64UrlDecode($parts[0]);
        print_r(json_decode($jsonString, true));
    }

    // =====================================================================
    // 2. THE ROUTER (Fast Offline Check)
    // =====================================================================
    public function routerFastCheck(string $jwsString): bool {
        try {
            $parts = explode('.', $jwsString);
            if (count($parts) !== 2) return false;

            $jsonString = SignVerifyUtils::base64UrlDecode($parts[0]);
            $envelope = json_decode($jsonString, true);

            if (!$envelope || !isset($envelope['data']) || !isset($envelope['checksum'])) return false;

            $dataStringToVerify = json_encode($envelope['data'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $calculatedChecksum = hash('sha256', $dataStringToVerify);

            return hash_equals($calculatedChecksum, $envelope['checksum']);
        } catch (Exception $e) {
            return false;
        }
    }

    // =====================================================================
    // 3. THE RECEIVER (Ticket Verifier)
    // =====================================================================
    public function verifyAndExtractTicket(string $base64String): array {
        $myTicket = TicketEncoder::decodeFromBase64($base64String);
        $parts = explode('.', $myTicket['signature'] ?? '');
        if (count($parts) !== 2) throw new Exception("Invalid JWS format");

        $base64Payload = $parts[0];
        $signature = $parts[1];

        $jsonString = SignVerifyUtils::base64UrlDecode($base64Payload);
        $envelope = json_decode($jsonString, true);

        $senderUuid = $envelope['issby'] ?? null;
        $keyId = $envelope['kid'] ?? null;

        if (!$senderUuid || !$keyId) {
            throw new Exception("Payload missing 'issby' or 'kid'. Cannot identify sender or key.");
        }

        $utils = new SignVerifyUtils($this->superAppDomain);
        $publicKeyPem = $utils->fetchPublicKey($senderUuid, $keyId);

        $rawSignature = SignVerifyUtils::base64UrlDecode($signature);
        $isValid = openssl_verify($base64Payload, $rawSignature, $publicKeyPem, OPENSSL_ALGO_SHA384);

        if ($isValid !== 1) {
            throw new Exception("CRITICAL: Signature verification failed. Data tampered with or invalid key.");
        }

        return $envelope['data'];
    }
}