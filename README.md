
# CamIE SuperApp SDK – Usage Guidelines

This guide covers the installation, initialization, and core methods for interacting with the CamIE SuperApp ecosystem using the PHP/Laravel SDK.

## Installation

Install the package via Composer:

```bash
composer require debc-camie/camie-superapp-sdk

```

## Set up environment
EdDSA: use to sign data with mobile or thirdparty with algorithm (secp384r1). Generate function
generate public/private keys: node js
```javascript
function generateKeyPair(): KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp384r1', // The curve you mentioned in previous code
        publicKeyEncoding: {
            type: 'spki', // Recommended standard for public keys
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8', // Recommended standard for private keys
            format: 'pem',
        },
    });

    return { publicKey, privateKey };
}
```
set up .env for laravel
```bash
TEST_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDYspqhkiy10B4xqoAK
YTGcjP0cjKyh1n3Ocvdt7de0wbcE8gqsPaQ+mADYWa2vpCihZANiAASbb0QR7DBS
1x/GwYkgxd5lbyuIRNLkzKxS1oL1JMw4ZoDJZfO0i2R3UactFsw22Z/ydHglD8qX
80u1qdyd8ZaVf3TcNsz/h8+LwX9vg9ckj/Ni6NKp6HdGaN93oNF8kfI=
-----END PRIVATE KEY-----"

SUPERAPPDOMAIN="https://some-other-domain.com"
```

## Initialization (Laravel)

If you need to connect dynamically to different environments or bypass the global Facade, you can instantiate the SDK directly in your controllers or services.

```php
use CamIE\SuperApp\CamIESuperAppSDK;

// Initialize the SDK with the target SuperApp domain
$superAppDomain=env('SUPERAPPDOMAIN');
$privateKey=env('TEST_PRIVATE_KEY');
$customSdk = new CamIESuperAppSDK($superAppDomain);
```

---

## 🎟️ Ticket Protocol

Tickets are specialized JWS (JSON Web Signature) payloads used for routing and verifying requests between MiniApps and the SuperApp.

### 1. `verifyAndExtractTicket()`

This is your primary method for receiving tickets. It securely fetches the sender's public key, verifies the ES384 signature, and extracts the core business data.

*Throws an Exception if the signature is invalid or tampered with.*

```php
$base64Ticket = "eyJ0eXBl...";

try {
    // Returns the associative array contained inside the ticket's 'data' property
    $data = $customSdk->verifyAndExtractTicket($base64Ticket);
    
    // Process your business logic
    $orderId = $data['some_fields'];
    
} catch (\Exception $e) {
    // Handle tampering, expired keys, or malformed data
    return response()->json(['error' => $e->getMessage()], 401);
}

```

### 2. `inspectTicket()`

Use this strictly for **debugging and logging**. It decodes and prints the ticket payload to the screen *without* verifying the cryptographic signature. Never use this for authentication.

```php
$base64Ticket = "eyJ0eXBl...";

// Directly outputs the decoded JSON payload to the console/browser
$customSdk->inspectTicket($base64Ticket);

```

---

## 🔑 Token Protocol

Tokens are standard 3-part JWTs used for secure data exchange and authentication.

### 1. `signToken()`

Generates a signed JWT using your Elliptic Curve (ES384/P-384) private key. It automatically injects the `iat` (Issued At), `jti` (JWT ID), and `scope` claims into your payload.

```php
$data = $customSdk->signToken(
        ['data'=>123, 'issby'=> "6a3a59fbed0de3f4dd4ba9dd"],
        $privateKey
    );
```

### 2. `verifyAndExtractToken()`

Validates an incoming JWT. It checks the signature against the sender's public key, ensures the token has not expired (maximum age: 10 minutes), and accounts for server clock skew.

```php
$jwtToken = "eyJhbGciOiJFUzM4NC...";

try {
    // Returns the fully decoded token envelope if verification passes
    $envelope = $customSdk->verifyAndExtractToken($jwtToken);
    
    $sender = $envelope['issby'];
    
} catch (\Exception $e) {
    // Fails on bad signatures, expired tokens, or missing claims
    return response()->json(['error' => 'Invalid Token: ' . $e->getMessage()], 401);
}

```

### 3. `inspectToken()`

A debugging helper that splits the 3-part JWT and prints both the Header and Payload arrays to the screen *without* cryptographic verification.

```php
$jwtToken = "eyJhbGciOiJFUzM4NC...";

// Directly outputs the decoded Header and Payload
$customSdk->inspectToken($jwtToken);

```