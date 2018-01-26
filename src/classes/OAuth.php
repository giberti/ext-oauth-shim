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
     * Make these protected|private once support for PHP 7.0 is dropped
     */
    const OAUTH_CALLBACK         = 'oauth_callback';
    const OAUTH_CONSUMER_KEY     = 'oauth_consumer_key';
    const OAUTH_CONSUMER_SECRET  = 'oauth_consumer_secret';
    const OAUTH_NONCE            = 'oauth_nonce';
    const OAUTH_SESSION_HANDLE   = 'oauth_session_handle';
    const OAUTH_SIGNATURE        = 'oauth_signature';
    const OAUTH_SIGNATURE_METHOD = 'oauth_signature_method';
    const OAUTH_TIMESTAMP        = 'oauth_timestamp';
    const OAUTH_TOKEN            = 'oauth_token';
    const OAUTH_TOKEN_SECRET     = 'oauth_token_secret';
    const OAUTH_VERIFIER         = 'oauth_verifier';
    const OAUTH_VERSION          = 'oauth_version';

    const EXCEPTION_MESSAGE_CONSUMER_KEY_EMPTY        = 'The consumer key cannot be empty';
    const EXCEPTION_MESSAGE_CONSUMER_KEY_SECRET_EMPTY = 'The consumer secret cannot be empty';
    const EXCEPTION_MESSAGE_INVALID_ACCESS_TOKEN_URL  = 'Invalid access token url length';
    const EXCEPTION_MESSAGE_INVALID_AUTH_TYPE         = 'Invalid auth type';
    const EXCEPTION_MESSAGE_INVALID_NONCE             = 'Invalid nonce';
    const EXCEPTION_MESSAGE_INVALID_REQUEST_ENGINE    = 'Invalid request engine specified';
    const EXCEPTION_MESSAGE_INVALID_REQUEST_TOKEN_URL = 'Invalid request token url length';
    const EXCEPTION_MESSAGE_INVALID_TIMESTAMP         = 'Invalid timestamp';
    const EXCEPTION_MESSAGE_INVALID_VERSION           = 'Invalid version';
    const EXCEPTION_MESSAGE_CERT_PARSE_ERROR          = 'Could not parse RSA certificate';

    const EXCEPTION_CODE_INTERNAL = 503;

    const EXCEPTION_MESSAGE_FETCH_TEMPLATE = 'Invalid auth/bad request (got a %d, expected HTTP/1.1 20X or a redirect)';

    // OAuth construction parts
    private $consumerKey;
    private $consumerSecret;
    private $nonce;
    private $signature;
    private $signatureMethod;
    private $timestamp;
    private $token;
    private $tokenSecret;
    private $version;

    // Internal function
    private $authType;
    private $redirects = true;
    private $requestEngine;
    private $rsaKey;
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
            throw new OAuthException(self::EXCEPTION_MESSAGE_CONSUMER_KEY_EMPTY, -1);
        }
        if (empty($consumer_secret)) {
            throw new OAuthException(self::EXCEPTION_MESSAGE_CONSUMER_KEY_SECRET_EMPTY, -1);
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
        if (!$this->generateSignature($http_method, $protected_resource_url, $extra_parameters)) {
            return false;
        }

        $finalUrl     = $protected_resource_url;
        $finalParams  = $extra_parameters;
        $finalMethod  = $http_method;
        $finalHeaders = $http_headers;

        // Gather OAuth parameters
        $oauthParams = [];
        if (isset($extra_parameters[self::OAUTH_CALLBACK])) {
            $oauthParams[self::OAUTH_CALLBACK] = $extra_parameters[self::OAUTH_CALLBACK];
        }
        $oauthParams += [
            self::OAUTH_CONSUMER_KEY     => $this->consumerKey,
            self::OAUTH_SIGNATURE_METHOD => $this->signatureMethod,
            self::OAUTH_NONCE            => $this->nonce,
            self::OAUTH_TIMESTAMP        => $this->timestamp,
            self::OAUTH_VERSION          => $this->version,
        ];
        if (isset($extra_parameters[self::OAUTH_VERIFIER])) {
            $oauthParams[self::OAUTH_VERIFIER] = $extra_parameters[self::OAUTH_VERIFIER];
        }
        if ($this->token) {
            $oauthParams[self::OAUTH_TOKEN] = $this->token;
        }
        $oauthParams[self::OAUTH_SIGNATURE] = $this->signature;

        // Place OAuth parameters where they belong
        switch ($this->authType) {
            case OAUTH_AUTH_TYPE_AUTHORIZATION:
                $http_headers['Authorization'] = $this->getRequestHeader($http_method, $protected_resource_url,
                    $extra_parameters);
                break;

            case OAUTH_AUTH_TYPE_FORM:
                if (is_array($extra_parameters)) {
                    $finalParams = array_merge($extra_parameters, $oauthParams);
                } elseif (empty($extra_parameters)) {
                    $finalParams = $oauthParams;
                } else {
                    $finalParams = $extra_parameters . '&' . http_build_query($oauthParams);
                }
                break;

            case OAUTH_AUTH_TYPE_URI:
                if (false === stripos($protected_resource_url, '?')) {
                    $finalUrl .= '?' . http_build_query($oauthParams);
                } else {
                    $finalUrl .= '&' . http_build_query($oauthParams);
                }
                break;

            case OAUTH_AUTH_TYPE_NONE:
                // Don't pass the authorization ¯\_(ツ)_/¯
                break;
        }

        // Pass the request to the appropriate engine
        $uaTemplate = 'Giberti/ext-oauth-shim (%s; PHP ' . phpversion() . ') ' . PHP_OS . ' (like PECL-OAuth/2.0.2)';
        switch ($this->requestEngine) {
            case OAUTH_REQENGINE_STREAMS:
                $http_headers['User-Agent'] = sprintf($uaTemplate, 'stream');
                $finalHeaders               = $this->buildHeaders($http_headers);
                $this->fetchStream($finalUrl, $finalParams, $finalMethod, $this->buildHeaders($finalHeaders));
                break;

            case OAUTH_REQENGINE_CURL:
                $http_headers['User-Agent'] = sprintf($uaTemplate, 'cURL');
                $finalHeaders               = $this->buildHeaders($http_headers);
                $this->fetchCurl($finalUrl, $finalParams, $finalMethod, $this->buildHeaders($finalHeaders));
                break;

        }

        if ($this->debug) {
            $this->debugInfo['headers_sent'] = implode("\n", $finalHeaders);
            $this->debugInfo['headers_recv'] = $this->lastResponseHeaders;
            $this->debugInfo['body_recv']    = $this->lastResponse;
        }

        // Raise an exception for 4xx/5xx codes
        $code = $this->lastResponseInfo['http_code'];
        if ($code >= 400) {
            $message                 = sprintf(self::EXCEPTION_MESSAGE_FETCH_TEMPLATE, $code);
            $exception               = new OAuthException($message, $code);
            $exception->lastResponse = $this->lastResponse;
            if ($this->debug) {
                $exception->debugInfo = $this->debugInfo;
            }

            throw $exception;
        }

        // Redirect
        if ($this->redirects && $code >= 300 && $code < 400) {
            // Reset the request
            $this->nonce     = null;
            $this->signature = null;
            $this->timestamp = null;
            $this->fetch($protected_resource_url, $extra_parameters, $http_method, $http_headers);
        }

        return true;
    }

    private function fetchCurl($url, $params, $method, $headers)
    {
        // Set the request options
        $options = [
            CURLOPT_HEADER         => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_URL            => $url,
            CURLOPT_FOLLOWLOCATION => false,
        ];

        if (!$this->sslChecks) {
            $options[CURLOPT_SSL_VERIFYPEER] = $this->sslChecks & OAUTH_SSLCHECK_PEER;
            $options[CURLOPT_SSL_VERIFYHOST] = $this->sslChecks & OAUTH_SSLCHECK_BOTH;
        }
        if ($this->caPath && $this->caInfo) {
            $options[CURLOPT_CAPATH] = $this->caPath;
            $options[CURLOPT_CAINFO] = $this->caInfo;
        }

        // Set the method specific options
        switch ($method) {
            case OAUTH_HTTP_METHOD_DELETE:
                $options[CURLOPT_CUSTOMREQUEST] = 'DELETE';
                if (is_array($params)) {
                    $options[CURLOPT_POSTFIELDS] = http_build_query($params);
                } else {
                    $options[CURLOPT_POSTFIELDS] = $params;
                }
                break;

            case OAUTH_HTTP_METHOD_GET:
                $options[CURLOPT_HTTPGET] = true;
                if (!empty($params)) {
                    if (is_array($params)) {
                        $additionalParams = http_build_query($params);
                    } else {
                        $additionalParams = $params;
                    }
                    if (stripos($options[CURLOPT_URL], '?')) {
                        $options[CURLOPT_URL] .= '&' . $additionalParams;
                    } else {
                        $options[CURLOPT_URL] .= '?' . $additionalParams;
                    }
                }
                break;

            case OAUTH_HTTP_METHOD_HEAD:
                $options[CURLOPT_NOBODY] = true;
                break;

            case OAUTH_HTTP_METHOD_PUT:
                $options[CURLOPT_CUSTOMREQUEST] = 'PUT';
                $options[CURLOPT_POSTFIELDS]    = $params;
                break;

            case OAUTH_HTTP_METHOD_POST:
            default:
                $options[CURLOPT_CUSTOMREQUEST] = $method;
                if (is_array($params)) {
                    $options[CURLOPT_POSTFIELDS] = http_build_query($params);
                } else {
                    $options[CURLOPT_POSTFIELDS] = $params;
                }
                break;
        }

        $curl = curl_init();
        curl_setopt_array($curl, $options);
        $response     = curl_exec($curl);
        $responseInfo = curl_getinfo($curl);
        curl_close($curl);

        $this->lastResponseHeaders = trim(substr($response, 0, $responseInfo['header_size']));
        $this->lastResponse        = substr($response, $responseInfo['header_size']);
        $this->lastResponseInfo    = [
            'url'           => $responseInfo['url'],
            'content_type'  => $responseInfo['content_type'],
            'http_code'     => $responseInfo['http_code'],
            'size_download' => $responseInfo['size_download'],
            'size_upload'   => $responseInfo['size_upload'],
        ];

        return true;
    }

    private function fetchStream($url, $params, $method, $headers)
    {
        throw new Exception('Not implemented');
    }

    /**
     * Converts key/value pairs into header strings
     *
     * @param array $headers
     *
     * @return array
     */
    private function buildHeaders(array $headers)
    {
        // Map the header key/value pairs to the format cURL|stream_context expects
        $headerLines = [];
        foreach ($headers as $key => $value) {
            $headerLines[] = "{$key}: {$value}";
        }

        return $headerLines;
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
        $this->signature = null;

        // Set the nonce, timestamp, and version if not yet set
        $this->nonce     = $this->nonce ?: uniqid();
        $this->timestamp = $this->timestamp ?: time();
        $this->version   = $this->version ?: '1.0';

        $params = [
            self::OAUTH_CONSUMER_KEY     => $this->consumerKey,
            self::OAUTH_SIGNATURE_METHOD => $this->signatureMethod,
            self::OAUTH_NONCE            => $this->nonce,
            self::OAUTH_TIMESTAMP        => $this->timestamp,
            self::OAUTH_VERSION          => $this->version,
        ];

        if ($this->token) {
            $params[self::OAUTH_TOKEN] = $this->token;
        }

        if (is_array($extra_parameters)) {
            $params += $extra_parameters;
        }

        $sbs    = oauth_get_sbs($http_method, $url, $params);
        $secret = oauth_urlencode($this->consumerSecret) . '&' . oauth_urlencode($this->tokenSecret);

        if ($this->debug) {
            $this->debugInfo['sbs'] = $sbs;
        }

        switch ($this->signatureMethod) {
            case OAUTH_SIG_METHOD_RSASHA1:
                if (!extension_loaded('openssl') || !function_exists('openssl_sign') || !$this->rsaKey) {
                    trigger_error('OpenSSL not installed');

                    return false;
                }

                if (openssl_sign($sbs, $signature, $this->rsaKey, OPENSSL_ALGO_SHA1)) {
                    $this->signature = base64_encode($signature);
                }

                break;

            case OAUTH_SIG_METHOD_HMACSHA1:
                $this->signature = base64_encode(hash_hmac('sha1', $sbs, $secret, true));
                break;

            case OAUTH_SIG_METHOD_HMACSHA256:
                $this->signature = base64_encode(hash_hmac('sha256', $sbs, $secret, true));
                break;

            case OAUTH_SIG_METHOD_PLAINTEXT:
                $this->signature = $secret;
                break;

            default:
                return false;
        }

        return $this->signature;
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
     * @throws OAuthException
     */
    public function getAccessToken(
        $access_token_url,
        $auth_session_handle = null,
        $verifier_token = null,
        $http_method = OAUTH_HTTP_METHOD_POST
    ) {
        if (empty($access_token_url)) {
            throw new OAuthException(self::EXCEPTION_MESSAGE_INVALID_ACCESS_TOKEN_URL, self::EXCEPTION_CODE_INTERNAL);
        }

        $params = [];
        if ($verifier_token) {
            $params[self::OAUTH_VERIFIER] = $verifier_token;
        } elseif (isset($_REQUEST[self::OAUTH_VERIFIER])) {
            $params[self::OAUTH_VERIFIER] = $_REQUEST[self::OAUTH_VERIFIER];
        }

        if (!empty($auth_session_handle)) {
            $params[self::OAUTH_SESSION_HANDLE] = $auth_session_handle;
        }

        $this->fetch($access_token_url, $params, $http_method);
        $response = $this->getLastResponse();
        parse_str($response, $token);

        return $token;
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
        if (!$this->signature && !$this->generateSignature($http_method, $url, $extra_parameters)) {
            return false;
        }

        $params = [];
        if (isset($extra_parameters[self::OAUTH_CALLBACK])) {
            $params[self::OAUTH_CALLBACK] = $extra_parameters[self::OAUTH_CALLBACK];
        }
        $params += [
            self::OAUTH_CONSUMER_KEY     => $this->consumerKey,
            self::OAUTH_SIGNATURE_METHOD => $this->signatureMethod,
            self::OAUTH_NONCE            => $this->nonce,
            self::OAUTH_TIMESTAMP        => $this->timestamp,
            self::OAUTH_VERSION          => $this->version,
        ];
        if (isset($extra_parameters[self::OAUTH_VERIFIER])) {
            $params[self::OAUTH_VERIFIER] = $extra_parameters[self::OAUTH_VERIFIER];
        }
        if ($this->token) {
            $params[self::OAUTH_TOKEN] = $this->token;
        }
        $params[self::OAUTH_SIGNATURE] = $this->signature;

        $header = 'OAuth ';
        foreach ($params as $key => $value) {
            $header .= $key . '="' . oauth_urlencode($value) . '",';
        }

        return substr($header, 0, -1);
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
     * @throws OAuthException
     */
    public function getRequestToken($request_token_url, $callback_url = null, $http_method = OAUTH_HTTP_METHOD_POST)
    {
        if (empty($request_token_url)) {
            throw new OAuthException(self::EXCEPTION_MESSAGE_INVALID_REQUEST_TOKEN_URL, self::EXCEPTION_CODE_INTERNAL);
        }

        $params = [];
        if (isset($callback_url)) {
            if (!empty($callback_url)) {
                $params[self::OAUTH_CALLBACK] = $callback_url;
            } else {
                $params[self::OAUTH_CALLBACK] = 'oob';
            }
        }

        $this->fetch($request_token_url, $params, $http_method);
        $response = $this->getLastResponse();
        parse_str($response, $token);

        return $token;
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

        throw new OAuthException(self::EXCEPTION_MESSAGE_INVALID_AUTH_TYPE, self::EXCEPTION_CODE_INTERNAL);
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
            throw new OAuthException(self::EXCEPTION_MESSAGE_INVALID_NONCE, self::EXCEPTION_CODE_INTERNAL);
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

        throw new OAuthException(self::EXCEPTION_MESSAGE_INVALID_REQUEST_ENGINE, self::EXCEPTION_CODE_INTERNAL);
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
        if (!extension_loaded('openssl') || !function_exists('openssl_pkey_get_private')) {
            trigger_error('OpenSSL not installed');

            return false;
        }

        $this->rsaKey = openssl_pkey_get_private($cert);
        if (!$this->rsaKey) {
            throw new OAuthException(self::EXCEPTION_MESSAGE_CERT_PARSE_ERROR, self::EXCEPTION_CODE_INTERNAL);
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
            throw new OAuthException(self::EXCEPTION_MESSAGE_INVALID_TIMESTAMP, self::EXCEPTION_CODE_INTERNAL);
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
            throw new OAuthException(self::EXCEPTION_MESSAGE_INVALID_VERSION, self::EXCEPTION_CODE_INTERNAL);
        }

        $this->version = $version;

        return true;
    }
}