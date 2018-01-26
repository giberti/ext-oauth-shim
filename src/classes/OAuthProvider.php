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


    const EXCEPTION_MESSAGE_SIGNATURE_MISMATCH = 'Signatures do not match';

    public function __construct(array $params_array = [])
    {

    }

    final public function addRequiredParameter($req_params)
    {

    }

    public function callConsumerHandler()
    {
        $response = call_user_func($this->consumerHandlerFunction, $this);
        switch ($response) {
            case OAUTH_OK;
                return;
            default:
                throw new \OAuthException('consumer issue', $response);
        }
    }

    public function callTimestampNonceHandler()
    {
        $response = call_user_func($this->timestampNonceHandlerFunction, $this);
        switch ($response) {
            case OAUTH_OK;
                return;
            default:
                throw new \OAuthException('timestamp nonce issue', $response);
        }
    }

    public function callTokenHandler()
    {
        $response = call_user_func($this->tokenHandlerFunction, $this);
        switch ($response) {
            case OAUTH_OK;
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
     * @throws OAuthException
     */
    public function checkOAuthRequest($uri = null, $method = null)
    {
        $uri    = isset($uri) ? $uri : $this->getRequestUri();
        $method = isset($method) ? $method : $this->getRequestMethod();

        $requestUrl    = $this->getFullRequestUrl($uri);
        $requestParams = $this->getRequestParams();
        $oauthParams   = $this->getOAuthParams();

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

    /*
        final public static string generateToken ( int $size [, bool $strong = false ] )
        public void is2LeggedEndpoint ( mixed $params_array )
        public void isRequestTokenEndpoint ( bool $will_issue_request_token )
        final public bool removeRequiredParameter ( string $req_params )
        final public static string reportProblem ( string $oauthexception [, bool $send_headers = true ] )
        final public bool setParam ( string $param_key [, mixed $param_val ] )
    */

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
        $requestUrl = 'http';
        if (isset($_SERVER['HTTPS'])) {
            $requestUrl .= 's';
        }
        $requestUrl .= '://' . $_SERVER['HTTP_HOST'];
        $requestUrl .= $uri;

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
     * @return array Parameters passed via query string or POST
     */
    private function getRequestParams()
    {
        return $_REQUEST;
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
     * Collect oauth_ params from Authorization header and URL
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

        return $params;
    }
}