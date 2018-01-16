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

$provider->setRequestTokenPath('/request-token.php');

try {
    $provider->checkOAuthRequest();
} catch (OAuthException $e) {
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
}

header('HTTP/1.1 200 OK');
echo 'oauth_token=' . oauth_urlencode('request-token') . '&oauth_token_secret=' . oauth_urlencode('request-secret');
