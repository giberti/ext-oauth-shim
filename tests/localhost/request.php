<?php

include __DIR__ . '/../../vendor/autoload.php';
$tokens = include __DIR__ . '/tokens.php';

$provider = new OAuthProvider();

$provider->consumerHandler(function ($provider) use ($tokens) {
    switch ($provider->consumer_key) {
        case 'consumer':
            $provider->consumer_secret = $tokens['consumer-tokens'][$provider->consumer_key];
            return OAUTH_OK;

        case 'consumer-refused':
            return OAUTH_CONSUMER_KEY_REFUSED;
    }

    return OAUTH_CONSUMER_KEY_UNKNOWN;
});

$provider->timestampNonceHandler(function ($provider) {
    switch ($provider->nonce) {
        case 'nonce-bad':
            return OAUTH_BAD_NONCE;
    }

    if (!is_numeric($provider->timestamp) || $provider->timestamp < 0) {
        return OAUTH_BAD_TIMESTAMP;
    }

    return OAUTH_OK;
});

$provider->tokenHandler(function ($provider) use ($tokens) {

    // Check the token
    switch ($provider->token) {
        case 'token':
            $provider->token_secret = $tokens['access-tokens'][$provider->token];
            break;

        case 'token-expired':
            return OAUTH_TOKEN_EXPIRED;

        default:
            return OAUTH_TOKEN_REJECTED;
    }

    return OAUTH_OK;
});

$provider->setRequestTokenPath('/request-token.php');

try {
    $provider->checkOAuthRequest();
} catch (OAuthException $e) {
    // Set an appropriate header
    switch ($e->getCode()) {
        case OAUTH_CONSUMER_KEY_REFUSED:
        case OAUTH_CONSUMER_KEY_UNKNOWN:
        case OAUTH_TOKEN_EXPIRED:
        case OAUTH_TOKEN_REJECTED:
        case OAUTH_TOKEN_USED:
        case OAUTH_VERIFIER_INVALID:
            header('HTTP/1.1 401 Unauthorized');
            break;

        case OAUTH_BAD_NONCE:
        case OAUTH_BAD_TIMESTAMP:
        case OAUTH_INVALID_SIGNATURE:
        case OAUTH_SIGNATURE_METHOD_REJECTED:
        default:
            header('HTTP/1.1 400 Bad Request');
    }

    echo 'OAuthException: ' . $e->getCode() . ': ' .$e->getMessage();
    return;
}

$status = isset($_GET['status']) ? $_GET['status'] : 200;
header('HTTP/1.1 ' . $status);
header('Content-type: application/json');
$data = [
    'get'   => $_GET,
    'post'  => $_POST,
    'input' => file_get_contents('php://input'),
];

echo json_encode($data);