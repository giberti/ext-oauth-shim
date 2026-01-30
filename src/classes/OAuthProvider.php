<?php

class OAuthProvider
{

    /**
     * @var string $callback
     */
    public $callback;

    /**
     * @var string $consumer_key
     */
    public $consumer_key;

    /**
     * @var string $consumer_secret
     */
    public $consumer_secret;

    /**
     * @var string $nonce
     */
    public $nonce;

    /**
     * @var string $signature
     */
    public $signature;

    /**
     * @var string $signature_method
     */
    public $signature_method;

    /**
     * @var string $timestamp
     */
    public $timestamp;

    /**
     * @var string token
     */
    public $token;

    /**
     * @var string $token_secret
     */
    public $token_secret;

    /**
     * @var string $verifier
     */
    public $verifier;

    /**
     * @var string $version
     */
    public $version;

    /**
     * @var callable $consumerHandlerFunction
     */
    protected $consumerHandlerFunction;

    /**
     * @var callable $timestampNonceHandlerFunction
     */
    protected $timestampNonceHandlerFunction;

    /**
     * @var callable $tokenHandlerFunction
     */
    protected $tokenHandlerFunction;

    /**
     * @var string $requestTokenPath
     */
    protected $requestTokenPath;

    /**
     * A list of required parameters for the request
     *
     * @var string[] $requiredParameters
     */
    private $requiredParameters = [];

    /**
     * @var array $constructorParams
     */
    private $constructorParams = [];

    const EXCEPTION_MESSAGE_MISSING_REQUIRED_PARAMS = 'Missing required parameters';
    const EXCEPTION_MESSAGE_SIGNATURE_MISMATCH      = 'Signatures do not match';

    /**
     * Create the provider object
     *
     * When the class is called via CLI, the `oauth_*` parameters that would be passed via Uri or Authorization header
     * should be included as the $params_array. In a more typical web request, they'll be parsed from the request
     * directly.
     *
     * @param array $params_array
     */
    public function __construct(array $params_array = [])
    {
        $this->constructorParams = $params_array;
    }

    /**
     * Marks a parameter as required for the request
     *
     * @param string $req_params
     *
     * @return bool
     */
    final public function addRequiredParameter($req_params)
    {
        return $this->requiredParameters[$req_params] = true;
    }

    public function callConsumerHandler()
    {
        $response = call_user_func($this->consumerHandlerFunction, $this);
        switch ($response) {
            case OAUTH_OK:
                return;
            default:
                throw new \OAuthException('consumer issue', $response);
        }
    }

    public function callTimestampNonceHandler()
    {
        $response = call_user_func($this->timestampNonceHandlerFunction, $this);
        switch ($response) {
            case OAUTH_OK:
                return;
            default:
                throw new \OAuthException('timestamp nonce issue', $response);
        }
    }

    public function callTokenHandler()
    {
        $response = call_user_func($this->tokenHandlerFunction, $this);
        switch ($response) {
            case OAUTH_OK:
                return OAUTH_OK;
            default:
                throw new \OAuthException('token issue', $response);
        }
    }

    /**
     * Check an oauth request
     *
     * @param string $uri
     * @param string $method
     *
     * @throws OAuthException
     */
    public function checkOAuthRequest($uri = null, $method = null)
    {
        $uri    = isset($uri) ? $uri : $this->getRequestUri();
        $method = isset($method) ? $method : $this->getRequestMethod();

        $requestUrl    = $this->getFullRequestUrl($uri);
        $requestParams = $this->getRequestParams();
        $oauthParams   = $this->getOAuthParams();

        // Check required parameters were passed where expected
        foreach ($this->requiredParameters as $key => $required) {
            if (!isset($this->constructorParams[$key])
                && !isset($oauthParams[$key])
            ) {
                $e = new OAuthException(self::EXCEPTION_MESSAGE_MISSING_REQUIRED_PARAMS, OAUTH_PARAMETER_ABSENT);
                $e->additionalInfo = $key;
                throw $e;
            }
        }

        // Set properties
        foreach ($oauthParams as $key => $value) {
            $key          = str_replace('oauth_', '', $key);
            $this->{$key} = $value;
        }

        // Call registered handlers
        $this->callTimestampNonceHandler();
        $this->callConsumerHandler();
        if ($this->requestTokenPath !== $uri) {
            // Don't call if this is a request token call
            $this->callTokenHandler();
        }

        // Validate the signature
        $oauth = new OAuth($this->consumer_key, $this->consumer_secret, $this->signature_method);
        $oauth->enableDebug();
        $oauth->setNonce($this->nonce);
        $oauth->setTimestamp($this->timestamp);
        $oauth->setVersion($this->version);
        if ($this->token) {
            $oauth->setToken($this->token, $this->token_secret);
        }

        $allParams = $requestParams + $oauthParams;

        // Remove sensitive parameters
        unset($allParams['oauth_consumer_secret']);
        unset($allParams['oauth_signature']);
        unset($allParams['oauth_token_secret']);

        $signature = $oauth->generateSignature($method, $requestUrl, $allParams);

        if ($this->signature !== $signature) {
            throw new OAuthException(self::EXCEPTION_MESSAGE_SIGNATURE_MISMATCH, OAUTH_INVALID_SIGNATURE);
        }

    }

    public function consumerHandler(callable $callback_function)
    {
        $this->consumerHandlerFunction = $callback_function;
    }

    /**
     * Generates a string of pseudo-random bytes.
     *
     * @param int  $size   The desired token length, in terms of bytes.
     * @param bool $strong Setting to TRUE means /dev/random will be used for entropy, as otherwise the non-blocking
     *                     /dev/urandom is used. This parameter is ignored on Windows.
     *
     * @return string The requested random bytes
     */
    final public static function generateToken($size, $strong = false)
    {
        if ($size < 1) {
            $message = 'OAuthProvider::generateToken(): Cannot generate token with a size of less than 1 or greater than ' . PHP_INT_MAX;
            trigger_error($message, E_USER_WARNING);

            if (PHP_MAJOR_VERSION >= 8) {
                throw new OAuthException($message);
            }
        }

        // PHP7 only!
        return random_bytes($size);
    }

    /**
     * The 2-legged flow, or request signing. It does not require a token.
     *
     * @param array $params_array
     *
     * @return void
     */
    public function is2LeggedEndpoint($params_array)
    {
        throw new Exception('Not implemented');
    }

    /**
     * Sets isRequestTokenEndpoint
     *
     * @param bool $will_issue_request_token Sets whether or not it will issue a request token, thus determining if
     *                                       OAuthProvider::tokenHandler() needs to be called.
     *
     * @return void
     */
    public function isRequestTokenEndpoint($will_issue_request_token)
    {
        throw new Exception('Not implemented');
    }

    /**
     * Removes a required parameter.
     *
     * @param string $req_params The required parameter to be removed.
     *
     * @return bool
     */
    final public function removeRequiredParameter($req_params)
    {
        unset($this->requiredParameters[$req_params]);

        return true;
    }

    /**
     * Pass in a problem as an OAuthException, with possible problems listed in the OAuth constants section.
     *
     * @param OAuthException $oauthexception
     * @param bool           $send_headers
     */
    final public static function reportProblem($oauthexception, $send_headers = true)
    {
        throw new Exception('Not implemented');
    }

    /**
     * Sets a parameter
     *
     * @param string $param_key The parameter key
     * @param mixed  $param_val The optional parameter value
     *
     * @return bool
     */
    final public function setParam($param_key, $param_val = null)
    {
        throw new Exception('Not implemented');
    }

    final public function setRequestTokenPath($path)
    {
        // @todo when would this return false?
        $this->requestTokenPath = $path;

        return true;
    }

    public function timestampNonceHandler(callable $callback_function)
    {
        $this->timestampNonceHandlerFunction = $callback_function;
    }

    public function tokenHandler(callable $callback_function)
    {
        $this->tokenHandlerFunction = $callback_function;
    }

    /**
     * Builds the URL the caller requested from the $_SERVER and passed Uri
     *
     * @param string $uri The local Uri `/oauth/request-token`
     *
     * @return string Fully qualified Url `https://example.com/oauth/request-token?foo=bar`
     */
    private function getFullRequestUrl($uri)
    {
        $request = parse_url($uri);

        // Detect scheme
        if (!isset($request['scheme'])) {
            $request['scheme'] = 'http';
            if (isset($_SERVER['HTTPS'])) {
                $request['scheme'] .= 's';
            }
        }

        // Detect host from request
        if (!isset($request['host']) && isset($_SERVER['HTTP_HOST'])) {
            $request['host'] = $_SERVER['HTTP_HOST'];
        }

        // Detect path
        if (!isset($request['path']) && isset($_SERVER['REQUEST_URI'])) {
            $request['path'] = $_SERVER['REQUEST_URI'];
        }

        // Detect query string
        if (!isset($request['query']) && isset($_SERVER['QUERY_STRING'])) {
            $request['query'] = $_SERVER['QUERY_STRING'];
        }

        // Combine into the full request url
        $requestUrl = $request['scheme'] . '://' . $request['host'] . $request['path'];
        if (isset($request['query'])) {
            $requestUrl .= '?' . $request['query'];
        }

        return $requestUrl;
    }

    /**
     * @return string The HTTP method used for this request
     */
    private function getRequestMethod()
    {
        return $_SERVER['REQUEST_METHOD'];
    }

    /**
     *
     * @return string The Uri that was requested
     */
    private function getRequestUri()
    {
        $uri   = $_SERVER['REQUEST_URI'];
        $parts = parse_url($uri);

        return $parts['path'];
    }

    /**
     * Get the Parameters passed via query string, POST or in the constructor
     *
     * @return array Parameters passed via query string or POST
     */
    private function getRequestParams()
    {
        $params = $_REQUEST;
        if (0 === count($params)) {
            foreach ($this->constructorParams as $key => $value) {
                $params[$key] = $value;
            }
        }

        return $params;
    }

    /**
     * Takes an OAuth authorization header and returns an associative array of oauth_* values
     *
     * @param string $header Of the form 'OAuth realm="http://example.com" oauth_consumer_key="consumer",
     *                       oauth_signature="signature"'
     *
     * @return array All oauth_* values in header
     *               [
     *                   'oauth_consumer_key' => 'consumer',
     *                   'oauth_signature'    => 'signature'
     *               ]
     */
    private function parseAuthorizationHeader($header)
    {
        $values = [];
        $header = substr($header, 5);
        $pairs  = explode(',', $header);
        foreach ($pairs as $pair) {
            $pair = trim($pair); // remove optional whitespace
            list($key, $value) = explode('=', $pair);
            if (0 === strpos($value, '"') || 0 === strpos($value, "'")) {
                // remove optional `'` or `"`
                $value = substr($value, 1, strlen($value) - 2);
            }
            $values[$key] = rawurldecode($value);
        }

        return $values;
    }

    /**
     * Collect oauth_ params from Authorization header, request or constructor values
     *
     * @return array $params;
     */
    private function getOAuthParams()
    {
        $params = [];

        // Pull parameters from Authorization header
        $header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : null;
        if ($header) {
            if ('oauth' === strtolower(substr($header, 0, 5))) {
                $params += $this->parseAuthorizationHeader($header);
            }
        }

        // Pull parameters from $_POST
        foreach ($_POST as $key => $value) {
            if ('oauth_' === substr($key, 0, 6)) {
                $params[$key] = $value;
            }
        }

        // Pull parameters from $_GET
        foreach ($_GET as $key => $value) {
            if ('oauth_' === substr($key, 0, 6)) {
                $params[$key] = $value;
            }
        }

        // Pull from constructor values
        foreach ($this->constructorParams as $key => $value) {
            if ('oauth_' === substr($key, 0, 6)) {
                $params[$key] = $value;
            }
        }

        return $params;
    }
}