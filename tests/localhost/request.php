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
    header('HTTP/1.1 400 Bad Request');
    header('Content-type: text/plain');
    echo $e->getMessage();
    return;
}

header('HTTP/1.1 200 OK');
header('Content-type: application/json');
$data = [
    'get' => $_GET,
    'post' => $_POST
];

echo json_encode($data);