<?php

namespace CamIE\SuperApp;

use Exception;

class SignVerifyUtils {

    public const MAX_TOKEN_AGE_SECONDS = 600;
    public const CLOCK_SKEW_TOLERANCE = 60;

    private const DEFAULT_SERVER_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEmQ3j53vdFndaUYv1pKpLWhwQsw1e0Xa4\nsJ1JrN0MJELquD4F1O8cAoQGBmxQX4F3tx6MeFMRqDk2eY07kkVb/UAEPZjA9bGG\nGPWFAXYGjvrEn7tmmCDc9IBQ14tH6DRL\n-----END PUBLIC KEY-----";

    public const CACHE_TTL_MS = 43200000; // 12 hours in milliseconds

    private string $superAppDomain;
    private array $jwksCache = []; // In-memory cache

    public function __construct(string $superAppDomain) {
        $this->superAppDomain = rtrim($superAppDomain, '/');
    }

    // =====================================================================
    // 🧰 UTILITIES
    // =====================================================================

    public static function base64UrlEncode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $data): string {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($data)) % 4));
    }

    public static function generateUuidV4(): string {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // Version 4
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // Variant 10
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    // =====================================================================
    // 🔒 CRYPTOGRAPHIC HELPERS
    // =====================================================================

    public function generateSignature(string $stringToSign, string $privateKeyPem): string {
        $signature = '';
        if (!openssl_sign($stringToSign, $signature, $privateKeyPem, OPENSSL_ALGO_SHA384)) {
            throw new Exception("Signature generation failed.");
        }
        return self::base64UrlEncode($signature);
    }

    public function fetchPublicKey(string $senderUuid, string $keyId): string {
        $cacheDir = getcwd() . '/.cache';
        $cacheFilePath = $cacheDir . "/jwks_cache_{$senderUuid}.json";

        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0777, true);
        }

        $jwksData = null;
        $currentTime = round(microtime(true) * 1000);

        // 1. CHECK IN-MEMORY CACHE
        if (isset($this->jwksCache[$senderUuid])) {
            $memoryCache = $this->jwksCache[$senderUuid];
            if (($currentTime - $memoryCache['timestamp']) <= self::CACHE_TTL_MS) {
                $jwksData = $memoryCache['keys'];
            } else {
                unset($this->jwksCache[$senderUuid]);
            }
        }

        // 2. CHECK FILE CACHE
        if (!$jwksData && file_exists($cacheFilePath)) {
            $fileContent = file_get_contents($cacheFilePath);
            $fileCache = json_decode($fileContent, true);
            if ($fileCache && ($currentTime - $fileCache['timestamp']) <= self::CACHE_TTL_MS) {
                $jwksData = $fileCache['keys'];
                $this->jwksCache[$senderUuid] = $fileCache; // Restore to memory cache
            }
        }

        // 3. FETCH FROM NETWORK
        if (!$jwksData) {
            $apiUrl = $senderUuid === 'superapp'
                ? "{$this->superAppDomain}/auth/.well-known/public/verification-keys.json"
                : "{$this->superAppDomain}/public/partner/publickey/{$senderUuid}";

            // Using file_get_contents for standard synchronous HTTP request
            $context = stream_context_create(['http' => ['ignore_errors' => true]]);
            $response = @file_get_contents($apiUrl, false, $context);
            $httpCode = isset($http_response_header[0]) ? (int)explode(' ', $http_response_header[0])[1] : 0;

            if ($response === false || $httpCode < 200 || $httpCode >= 300) {
                if ($senderUuid === 'superapp') {
                    error_log("⚠️ [SignVerifyUtils] Network fetch failed. Using hardcoded emergency key.");
                    return self::DEFAULT_SERVER_PUBLIC_KEY;
                }
                throw new Exception("CRITICAL: Failed to fetch JWKS from network. HTTP {$httpCode}");
            }

            $jwks = json_decode($response, true);
            $jwksData = $senderUuid === 'superapp' ? ($jwks['keys'] ?? null) : ($jwks['data'] ?? null);

            if ($jwksData) {
                $cachePayload = [
                    'timestamp' => $currentTime,
                    'keys' => $jwksData
                ];
                $this->jwksCache[$senderUuid] = $cachePayload;
                @file_put_contents($cacheFilePath, json_encode($cachePayload, JSON_PRETTY_PRINT));
            }
        }

        // 4. FIND THE MATCHING KEY
        $matchingJwk = null;
        foreach ($jwksData as $k) {
            if (($k['kid'] ?? '') === $keyId) {
                $matchingJwk = $k;
                break;
            }
        }

        if (!$matchingJwk) {
            throw new Exception("CRITICAL: Public key with kid '{$keyId}' was revoked or not found.");
        }

        return $this->jwkToPem($matchingJwk);
    }

    /**
     * Converts a raw JWK into an OpenSSL-compatible PEM string
     */
    private function jwkToPem(array $jwk): string {
        // If x509 cert chain is provided, we can directly format it
        if (isset($jwk['x5c'][0])) {
            return "-----BEGIN CERTIFICATE-----\n" . chunk_split($jwk['x5c'][0], 64, "\n") . "-----END CERTIFICATE-----\n";
        }

        // Basic transformation for EC (Elliptic Curve) standard keys matching ES384/P-384
        if (isset($jwk['kty']) && $jwk['kty'] === 'EC') {
            $x = self::base64UrlDecode($jwk['x']);
            $y = self::base64UrlDecode($jwk['y']);
            
            // ASN.1 encoding prefix specifically for P-384
            $prefixHex = '3076301006072a8648ce3d020106052b8104002203620004';
            $keyHex = bin2hex($x) . bin2hex($y);
            $der = hex2bin($prefixHex . $keyHex);

            return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
        }

        throw new Exception("Unsupported JWK key type formatting fallback.");
    }
}