<?php

namespace CamIE\SuperApp;

use Exception;

class CamIESuperAppSDK {

    private string $superAppDomain;

    public function __construct(string $superAppDomain) {
        $this->superAppDomain = rtrim($superAppDomain, '/');
    }

    // =====================================================================
    // 🎟️ TICKET PROTOCOL METHODS
    // =====================================================================

    /**
     * Inspects a Ticket's JWS format and logs the payload without verifying the signature.
     */
    public function inspectTicket(string $jwsString): void {
        (new SuperApp_Ticket_Protocol($this->superAppDomain))->inspectTicket($jwsString);
    }

    /**
     * Verifies the Ticket's signature using the sender's public key and extracts the core data.
     */
    public function verifyAndExtractTicket(string $base64String): array {
        return (new SuperApp_Ticket_Protocol($this->superAppDomain))->verifyAndExtractTicket($base64String);
    }

    // =====================================================================
    // 🔑 TOKEN PROTOCOL METHODS
    // =====================================================================

    /**
     * Generates a signed standard 3-part JWT Token.
     */
    public function signToken(
        array $payloadData,
        string $privateKeyPem,
        string $keyId = 'key_v1_79715956'
    ): string {
        return (new SuperApp_Token_Protocol($this->superAppDomain))->signToken(
            $payloadData,
            $privateKeyPem,
            $keyId
        );
    }

    /**
     * Inspects a JWT Token and logs the header and payload without verifying the signature.
     */
    public function inspectToken(string $jwtString): void {
        (new SuperApp_Token_Protocol($this->superAppDomain))->inspectToken($jwtString);
    }

    /**
     * Verifies the Token's signature, checks expiration/skew, and extracts the envelope.
     */
    public function verifyAndExtractToken(string $jwtString): array {
        return (new SuperApp_Token_Protocol($this->superAppDomain))->verifyAndExtractToken($jwtString);
    }
}