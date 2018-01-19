<?php

/**
 * Class OAuth
 *
 * The OAuth extension provides a simple interface to interact with data providers using the OAuth HTTP specification
 * to protect private resources.
 *
 * @see http://php.net/manual/en/class.oauth.php
 */
class OAuth
{

    /**
     * The debug member can be set to a non-FALSE value to turn debug on
     *
     * @see disableDebug()
     * @see enableDebug()
     *
     * @var bool $debug
     */
    public $debug = false;

    /**
     * The sslChecks member can be set to FALSE to turn SSL checks off
     *
     * @see disableSSLChecks()
     * @see enableSSLChecks()
     *
     * @var bool $sslChecks
     */
    public $sslChecks = true;

    /**
     * @var $debugInfo
     */
    public $debugInfo;

    /**
     * OAuth constants
     *
     * Make these protected once support for PHP 7.0 is dropped
     */
    const OAUTH_CALLBACK         = 'oauth_callback';
    const OAUTH_CONSUMER_KEY     = 'oauth_consumer_key';
    const OAUTH_CONSUMER_SECRET  = 'oauth_consumer_secret';
    const OAUTH_NONCE            = 'oauth_nonce';
    const OAUTH_SIGNATURE        = 'oauth_signature';
    const OAUTH_SIGNATURE_METHOD = 'oauth_signature_method';
    const OAUTH_TIMESTAMP        = 'oauth_timestamp';
    const OAUTH_TOKEN            = 'oauth_token';
    const OAUTH_TOKEN_SECRET     = 'oauth_token_secret';
    const OAUTH_VERIFIER         = 'oauth_verifier';

    const EXCEPTION_MESSAGE_CONSUMER_KEY_EMPTY        = 'The consumer key cannot be empty';
    const EXCEPTION_MESSAGE_CONSUMER_KEY_SECRET_EMPTY = 'The consumer secret cannot be empty';
    const EXCEPTION_MESSAGE_INVALID_AUTH_TYPE         = 'Invalid auth type';
    const EXCEPTION_MESSAGE_INVALID_NONCE             = 'Invalid nonce';
    const EXCEPTION_MESSAGE_INVALID_REQUEST_ENGINE    = 'Invalid request engine specified';
    const EXCEPTION_MESSAGE_INVALID_TIMESTAMP         = 'Invalid timestamp';
    const EXCEPTION_MESSAGE_INVALID_VERSION           = 'Invalid version';
    const EXCEPTION_MESSAGE_CERT_PARSE_ERROR          = 'Could not parse RSA certificate';

    const EXCEPTION_CODE_INTERNAL = 503;

    const OAUTH_FETCH_MESSAGE = 'Invalid auth/bad request (got a %d, expected HTTP/1.1 20X or a redirect)';

    // OAuth construction parts
    private $consumerKey;
    private $consumerSecret;
    private $signatureMethod;
    private $token;
    private $tokenSecret;

    // Internal function
    private $authType;
    private $requestEngine;
    private $rsaCert;
    private $caInfo;
    private $caPath;

    // Return values
    private $lastResponse;
    private $lastResponseHeaders;
    private $lastResponseInfo;

    /**
     * Creates a new OAuth object
     *
     * @see http://php.net/manual/en/oauth.construct.php
     *
     * @param string $consumer_key     The consumer key provided by the service
     *                                 provider.
     * @param string $consumer_secret  The consumer secret provided by the
     *                                 service provider.
     * @param string $signature_method This optional parameter defines which
     *                                 signature method to use, by default it is
     *                                 OAUTH_SIG_METHOD_HMACSHA1 (HMAC-SHA1).
     * @param int    $auth_type        This optional parameter defines how to pass
     *                                 the OAuth parameters to a consumer, by default it is
     *                                 OAUTH_AUTH_TYPE_AUTHORIZATION (in the Authorization
     *                                 header).
     *
     * @throws OAuthException
     */
    public function __construct(
        $consumer_key = null,
        $consumer_secret = null,
        $signature_method = OAUTH_SIG_METHOD_HMACSHA1,
        $auth_type = OAUTH_AUTH_TYPE_AUTHORIZATION
    ) {
        if (empty($consumer_key)) {
            throw new OAuthException(static::EXCEPTION_MESSAGE_CONSUMER_KEY_EMPTY, -1);
        }
        if (empty($consumer_secret)) {
            throw new OAuthException(static::EXCEPTION_MESSAGE_CONSUMER_KEY_SECRET_EMPTY, -1);
        }

        $this->consumerKey     = $consumer_key;
        $this->consumerSecret  = $consumer_secret;
        $this->signatureMethod = $signature_method;
        $this->setAuthType($auth_type);

        if (extension_loaded('curl')) {
            $this->requestEngine = OAUTH_REQENGINE_CURL;
        } else {
            $this->requestEngine = OAUTH_REQENGINE_STREAMS;
        }
    }

    /**
     * Turns off verbose request information (off by default). Alternatively,
     * the debug property can be set to a FALSE value to turn debug off.
     *
     * @see http://php.net/manual/en/oauth.disabledebug.php
     *
     * @return bool
     */
    public function disableDebug()
    {
        $this->debug = false;

        return true;
    }

    /**
     * Disable redirects from being followed automatically, thus allowing the
     * request to be manually redirected.
     *
     * @see http://php.net/manual/en/oauth.disableredirects.php
     *
     * @return bool
     */
    public function disableRedirects()
    {
        $this->redirects = false;

        return true;
    }

    /**
     * Turns off the usual SSL peer certificate and host checks, this is not
     * for production environments. Alternatively, the sslChecks member can be
     * set to FALSE to turn SSL checks off.
     *
     * @see http://php.net/manual/en/oauth.disablesslchecks.php
     *
     * @return bool
     */
    public function disableSSLChecks()
    {
        $this->sslChecks = OAUTH_SSLCHECK_NONE;

        return true;
    }

    /**
     * Turns on verbose request information useful for debugging, the debug
     * information is stored in the debugInfo member. Alternatively, the debug
     * member can be set to a non-FALSE value to turn debug on.
     *
     * @see http://php.net/manual/en/oauth.enabledebug.php
     *
     * @return bool
     */
    public function enableDebug()
    {
        $this->debug = true;

        return true;
    }

    /**
     * Follow and sign redirects automatically, which is enabled by default.
     *
     * @see http://php.net/manual/en/oauth.enableredirects.php
     *
     * @return bool
     */
    public function enableRedirects()
    {
        $this->redirects = true;

        return true;
    }

    /**
     * Turns on the usual SSL peer certificate and host checks (enabled by
     * default). Alternatively, the sslChecks member can be set to a non-FALSE
     * value to turn SSL checks off.
     *
     * @see http://php.net/manual/en/oauth.enablesslchecks.php
     *
     * @return bool
     */
    public function enableSSLChecks()
    {
        $this->sslChecks = OAUTH_SSLCHECK_BOTH;

        return true;
    }

    /**
     * Fetch a resource.
     *
     * @see http://php.net/manual/en/oauth.fetch.php
     *
     * @param string       $protected_resource_url
     * @param array|string $extra_parameters
     * @param string       $http_method
     * @param array        $http_headers
     *
     * @return bool Returns TRUE on success or FALSE on failure.
     * @throws OAuthException
     */
    public function fetch(
        $protected_resource_url,
        $extra_parameters = null,
        $http_method = OAUTH_HTTP_METHOD_GET,
        array $http_headers = []
    ) {
        throw new Exception('Not implemented');
    }


    /**
     * Generate a signature based on the final HTTP method, URL and a string/array of parameters.
     *
     * @see http://php.net/manual/en/oauth.generatesignature.php
     *
     * @param string       $http_method      HTTP method for request
     * @param string       $url              URL for request
     * @param string|array $extra_parameters String or array of additional parameters.
     *
     * @return string|false A string containing the generated signature or FALSE on failure
     * @throws OAuthException
     */
    public function generateSignature($http_method, $url, $extra_parameters)
    {
        throw new Exception('Not implemented');
    }

    /**
     * Fetch an access token, secret and any additional response parameters
     * from the service provider.
     *
     * @see http://php.net/manual/en/oauth.getaccesstoken.php
     *
     * @param string $access_token_url    URL to the access token API.
     * @param string $auth_session_handle Authorization session handle, this parameter does not have any citation in
     *                                    the core OAuth 1.0 specification but may be implemented by large providers.
     * @param string $verifier_token      For service providers which support 1.0a, a verifier_token must be passed
     *                                    while exchanging the request token for the access token. If the
     *                                    verifier_token is present in $_GET or $_POST it is passed automatically and
     *                                    the caller does not need to specify a verifier_token (usually if the access
     *                                    token is exchanged at the oauth_callback URL).
     * @param string $http_method         HTTP method to use, e.g. GET or POST.
     *
     * @return array|false Returns an array containing the parsed OAuth
     *          response on success or FALSE on failure.
     */
    public function getAccessToken($access_token_url, $auth_session_handle, $verifier_token, $http_method)
    {
        throw new Exception('Not implemented');
    }

    /**
     * Gets the Certificate Authority information, which includes the ca_path
     * and ca_info set by static::setCAPath().
     *
     * @see http://php.net/manual/en/oauth.getcapath.php
     *
     * @return array An array of Certificate Authority information,
     *          specifically as ca_path and ca_info keys within the returned
     *          associative array.
     */
    public function getCAPath()
    {
        return [
            'ca_info' => $this->caInfo,
            'ca_path' => $this->caPath,
        ];
    }

    /**
     * Get the raw response of the most recent request.
     *
     * @see http://php.net/manual/en/oauth.getlastresponse.php
     *
     * @return string Returns a string containing the last response.
     */
    public function getLastResponse()
    {
        return $this->lastResponse;
    }

    /**
     * Returns a string containing the last response.
     *
     * @see http://php.net/manual/en/oauth.getlastresponseheaders.php
     *
     * @return string|false A string containing the last response's headers or
     *          FALSE on failure
     */
    public function getLastResponseHeaders()
    {
        return $this->lastResponseHeaders;
    }

    /**
     * Get HTTP information about the last response.
     *
     * @see http://php.net/manual/en/oauth.getlastresponseinfo.php
     *
     * @return array
     */
    public function getLastResponseInfo()
    {
        return $this->lastResponseInfo;
    }

    /**
     * Generate OAuth header string signature based on the final HTTP method, U
     * RL and a string/array of parameters
     *
     * @see http://php.net/manual/en/oauth.getrequestheader.php
     *
     * @return string A string containing the generated request header or FALSE
     *          on failure
     */
    public function getRequestHeader($http_method, $url, $extra_parameters)
    {
        throw new Exception('Not implemented');
    }

    /**
     * Fetch a request token, secret and any additional response parameters
     * from the service provider.
     *
     * @see http://php.net/manual/en/oauth.getrequesttoken.php
     *
     * @param string $request_token_url URL to the request token API.
     * @param string $callback_url      OAuth callback URL. If $callback_url is
     *                                  passed and is an empty value, it is set to "oob" to address the
     *                                  OAuth 2009.1 advisory.
     * @param string $http_method       HTTP method to use, e.g. GET or POST.
     *
     * @return string
     */
    public function getRequestToken($request_token_url, $callback_url, $http_method)
    {
        throw new Exception('Not implemented');
    }

    /**
     * Set where the OAuth parameters should be passed.
     *
     * @see http://php.net/manual/en/oauth.setauthtype.php
     *
     * @param int $auth_type Auth_type can be one of the pre-defined
     *                       OAUTH_AUTH_* constants flags
     *
     * @return bool Returns TRUE if a parameter is correctly set, otherwise
     *          FALSE (e.g., if an invalid auth_type is passed in.)
     *
     * @throws OAuthException
     */
    public function setAuthType($auth_type)
    {
        switch ($auth_type) {
            case OAUTH_AUTH_TYPE_AUTHORIZATION:
            case OAUTH_AUTH_TYPE_FORM:
            case OAUTH_AUTH_TYPE_NONE:
            case OAUTH_AUTH_TYPE_URI:
                $this->authType = $auth_type;

                return true;
        }

        throw new OAuthException(static::EXCEPTION_MESSAGE_INVALID_AUTH_TYPE, 503);
    }

    /**
     * @see http://php.net/manual/en/oauth.setcapath.php
     *
     * @param string $ca_path
     * @param string $ca_info
     *
     * @return true
     */
    public function setCAPath($ca_path, $ca_info)
    {
        $this->caPath = $ca_path;
        $this->caInfo = $ca_info;

        return true;
    }

    /**
     * Sets the nonce for all subsequent requests.
     *
     * @see http://php.net/manual/en/oauth.setnonce.php
     *
     * @param string $nonce The value for oauth_nonce.
     *
     * @return bool Returns TRUE on success, or FALSE if the nonce is
     *          considered invalid.
     * @throws OAuthException
     */
    public function setNonce($nonce)
    {
        if (strlen($nonce) < 1) {
            throw new OAuthException(static::EXCEPTION_MESSAGE_INVALID_NONCE, static::EXCEPTION_CODE_INTERNAL);
        }

        $this->nonce = $nonce;

        return true;
    }

    /**
     * Sets the Request Engine, that will be sending the HTTP requests.
     *
     * @see http://php.net/manual/en/oauth.setrequestengine.php
     *
     * @param int $reqengine The desired request engine. Set to
     *                       OAUTH_REQENGINE_STREAMS to use PHP Streams, or
     *                       OAUTH_REQENGINE_CURL to use Curl.
     *
     * @return void
     * @throws OAuthException Emits an OAuthException exception if an invalid
     *          request engine is chosen.
     */
    public function setRequestEngine($reqengine)
    {
        $validEngines = [
            OAUTH_REQENGINE_STREAMS => true,
        ];
        if (extension_loaded('curl')) {
            $validEngines[OAUTH_REQENGINE_CURL] = true;
        }

        if (isset($validEngines[$reqengine])) {
            $this->requestEngine = $reqengine;

            return;
        }

        throw new OAuthException(static::EXCEPTION_MESSAGE_INVALID_REQUEST_ENGINE, static::EXCEPTION_CODE_INTERNAL);
    }

    /**
     * Sets the RSA certificate.
     *
     * @see http://php.net/manual/en/oauth.setrsacertificate.php
     *
     * @param string $cert The RSA certificate.
     *
     * @return bool Returns TRUE on success, or FALSE on failure (e.g., the RSA
     *          certificate cannot be parsed.)
     * @throws OAuthException
     */
    public function setRSACertificate($cert)
    {
        if (!function_exists('openssl_pkey_get_private')) {
            return false;
        }

        $this->rsaCert = openssl_pkey_get_private($cert);
        if (!$this->rsaCert) {
            throw new OAuthException(static::EXCEPTION_MESSAGE_CERT_PARSE_ERROR, static::EXCEPTION_CODE_INTERNAL);
        }

        return true;
    }

    /**
     * Tweak specific SSL checks for requests.
     *
     * @see http://php.net/manual/en/oauth.setsslchecks.php
     *
     * @param int $sslcheck
     *
     * @return bool Returns TRUE on success or FALSE on failure.
     */
    public function setSSLChecks($sslcheck)
    {
        switch ($sslcheck) {
            case OAUTH_SSLCHECK_HOST:
            case OAUTH_SSLCHECK_PEER:
            case OAUTH_SSLCHECK_NONE:
            case OAUTH_SSLCHECK_BOTH:
                $this->sslChecks = $sslcheck & OAUTH_SSLCHECK_BOTH;
        }

        return true;
    }

    /**
     * Sets the OAuth timestamp for subsequent requests.
     *
     * @see http://php.net/manual/en/oauth.settimestamp.php
     *
     * @param int $timestamp The timestamp.
     *
     * @return bool Returns TRUE, unless the timestamp is invalid, in which
     *          case FALSE is returned.
     * @throws OAuthException
     */
    public function setTimestamp($timestamp)
    {
        if (strlen($timestamp) < 1) {
            throw new OAuthException(static::EXCEPTION_MESSAGE_INVALID_TIMESTAMP, static::EXCEPTION_CODE_INTERNAL);
        }

        $this->timestamp = $timestamp;

        return true;
    }


    /**
     * Set the token and secret for subsequent requests.
     *
     * @see http://php.net/manual/en/oauth.settoken.php
     *
     * @param string $token        The OAuth token.
     * @param string $token_secret The OAuth token secret.
     *
     * @return bool
     */
    public function setToken($token, $token_secret)
    {
        $this->token       = $token;
        $this->tokenSecret = $token_secret;

        return true;
    }

    /**
     * Sets the OAuth version for subsequent requests
     *
     * @see http://php.net/manual/en/oauth.setversion.php
     *
     * @param string $version OAuth version, default value is always "1.0"
     *
     * @return bool Returns TRUE on success or FALSE on failure.
     * @throws OAuthException
     */
    public function setVersion($version)
    {
        if (strlen($version) < 1) {
            throw new OAuthException(static::EXCEPTION_MESSAGE_INVALID_VERSION, 503);
        }

        $this->version = $version;

        return true;
    }
}