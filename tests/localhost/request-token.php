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
    header('HTTP/1.1 400 Bad Request');
    echo $e->getMessage();
    return;
}

header('HTTP/1.1 200 OK');
echo 'oauth_token=' . oauth_urlencode('request-token') . '&oauth_token_secret=' . oauth_urlencode('request-secret');
