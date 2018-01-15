<?php

include __DIR__ . '/../../vendor/autoload.php';
$tokens = include __DIR__ . '/tokens.php';

$provider = new OAuthProvider();
$provider->addRequiredParameter('oauth_verifier');

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
        case 'request-token':
            $provider->token_secret = $tokens['request-tokens'][$provider->token];
            break;

        case 'request-token-expired':
            return OAUTH_TOKEN_EXPIRED;

        default:
            return OAUTH_TOKEN_REJECTED;
    }

    // Check the verifier
    if ($provider->verifier && $provider->verifier != $tokens['request-token-verifier']) {
        return OAUTH_VERIFIER_INVALID;
    }

    return OAUTH_OK;
});

$provider->setRequestTokenPath('/request-token.php');

try {
    $provider->checkOAuthRequest();
} catch (OAuthException $e) {
    header('HTTP/1.1 400 Bad Request');
    echo $e->getMessage();
    return;
}

header('HTTP/1.1 200 OK');
echo 'oauth_token=' . oauth_urlencode('token') . '&oauth_token_secret=' . oauth_urlencode('secret');
