<?php

/**
 * Provides the non-namespaced constants provided by PECL OAuth extension
 */

if (extension_loaded('oauth')) {
    return;
}

if (!defined('OAUTH_SIG_METHOD_RSASHA1')) {
    define('OAUTH_SIG_METHOD_RSASHA1', 'RSA-SHA1');
}
if (!defined('OAUTH_SIG_METHOD_HMACSHA1')) {
    define('OAUTH_SIG_METHOD_HMACSHA1', 'HMAC-SHA1');
}
if (!defined('OAUTH_SIG_METHOD_HMACSHA256')) {
    define('OAUTH_SIG_METHOD_HMACSHA256', 'HMAC-SHA256');
}
if (!defined('OAUTH_SIG_METHOD_PLAINTEXT')) {
    define('OAUTH_SIG_METHOD_PLAINTEXT', 'PLAINTEXT');
}

if (!defined('OAUTH_AUTH_TYPE_AUTHORIZATION')) {
    define('OAUTH_AUTH_TYPE_AUTHORIZATION', 3);
}
if (!defined('OAUTH_AUTH_TYPE_NONE')) {
    define('OAUTH_AUTH_TYPE_NONE', 4);
}
if (!defined('OAUTH_AUTH_TYPE_URI')) {
    define('OAUTH_AUTH_TYPE_URI', 1);
}
if (!defined('OAUTH_AUTH_TYPE_FORM')) {
    define('OAUTH_AUTH_TYPE_FORM', 2);
}

if (!defined('OAUTH_HTTP_METHOD_GET')) {
    define('OAUTH_HTTP_METHOD_GET', 'GET');
}
if (!defined('OAUTH_HTTP_METHOD_POST')) {
    define('OAUTH_HTTP_METHOD_POST', 'POST');
}
if (!defined('OAUTH_HTTP_METHOD_PUT')) {
    define('OAUTH_HTTP_METHOD_PUT', 'PUT');
}
if (!defined('OAUTH_HTTP_METHOD_HEAD')) {
    define('OAUTH_HTTP_METHOD_HEAD', 'HEAD');
}
if (!defined('OAUTH_HTTP_METHOD_DELETE')) {
    define('OAUTH_HTTP_METHOD_DELETE', 'DELETE');
}

if (!defined('OAUTH_REQENGINE_STREAMS')) {
    define('OAUTH_REQENGINE_STREAMS', 1);
}
if (!defined('OAUTH_REQENGINE_CURL')) {
    define('OAUTH_REQENGINE_CURL', 2);
}

if (!defined('OAUTH_SSLCHECK_NONE')) {
    define('OAUTH_SSLCHECK_NONE', 0);
}
if (!defined('OAUTH_SSLCHECK_HOST')) {
    define('OAUTH_SSLCHECK_HOST', 1);
}
if (!defined('OAUTH_SSLCHECK_PEER')) {
    define('OAUTH_SSLCHECK_PEER', 2);
}
if (!defined('OAUTH_SSLCHECK_BOTH')) {
    define('OAUTH_SSLCHECK_BOTH', 3);
}

if (!defined('OAUTH_OK')) {
    define('OAUTH_OK', 0);
}
if (!defined('OAUTH_BAD_NONCE')) {
    define('OAUTH_BAD_NONCE', 4);
}
if (!defined('OAUTH_BAD_TIMESTAMP')) {
    define('OAUTH_BAD_TIMESTAMP', 8);
}
if (!defined('OAUTH_CONSUMER_KEY_UNKNOWN')) {
    define('OAUTH_CONSUMER_KEY_UNKNOWN', 16);
}
if (!defined('OAUTH_CONSUMER_KEY_REFUSED')) {
    define('OAUTH_CONSUMER_KEY_REFUSED', 32);
}
if (!defined('OAUTH_INVALID_SIGNATURE')) {
    define('OAUTH_INVALID_SIGNATURE', 64);
}
if (!defined('OAUTH_TOKEN_USED')) {
    define('OAUTH_TOKEN_USED', 128);
}
if (!defined('OAUTH_TOKEN_EXPIRED')) {
    define('OAUTH_TOKEN_EXPIRED', 256);
}
if (!defined('OAUTH_TOKEN_REVOKED')) {
    define('OAUTH_TOKEN_REVOKED', 512);
}
if (!defined('OAUTH_TOKEN_REJECTED')) {
    define('OAUTH_TOKEN_REJECTED', 1024);
}
if (!defined('OAUTH_VERIFIER_INVALID')) {
    define('OAUTH_VERIFIER_INVALID', 2048);
}
if (!defined('OAUTH_PARAMETER_ABSENT')) {
    define('OAUTH_PARAMETER_ABSENT', 4096);
}
if (!defined('OAUTH_SIGNATURE_METHOD_REJECTED')) {
    define('OAUTH_SIGNATURE_METHOD_REJECTED', 8192);
}
