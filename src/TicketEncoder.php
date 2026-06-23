<?php

namespace CamIE\SuperApp;

use Exception;

class TicketEncoder {

    /**
     * Encodes an associative array into a Base64URL string.
     */
    public static function encodeToBase64(array $ticket): string {
        try {
            // Unescaped slashes and unicode are strictly required to match Node's JSON.stringify format
            $jsonString = json_encode($ticket, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($jsonString === false) {
                throw new Exception("JSON encoding failed.");
            }
            return SignVerifyUtils::base64UrlEncode($jsonString);
        } catch (Exception $error) {
            throw new Exception("Failed to encode ticket to Base64");
        }
    }

    /**
     * Decodes a Base64URL string back into an associative array.
     */
    public static function decodeFromBase64(string $base64String): array {
        try {
            $jsonString = SignVerifyUtils::base64UrlDecode($base64String);
            $decoded = json_decode($jsonString, true);
            if ($decoded === null) {
                throw new Exception("JSON decoding failed.");
            }
            return $decoded;
        } catch (Exception $error) {
            throw new Exception("Failed to decode Base64 string to JSON. The payload might be corrupted.");
        }
    }
}