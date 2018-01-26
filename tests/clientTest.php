<?php

use Giberti\PHPUnitLocalServer\LocalServerTestCase;

class ClientTest extends LocalServerTestCase
{

    /**
     * Holds the assorted test tokens and secrets the client and server will need
     *
     * @var array
     */
    public static $tokens;

    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();
        $docRoot   = __DIR__ . '/localhost';
        $tokenFile = $docRoot . '/tokens.php';
        if (!file_exists($tokenFile)) {
            trigger_error('Unable to read token file');
        }
        static::$tokens = include $tokenFile;
        // Start the server
        static::createServerWithDocroot($docRoot);
    }

    public function test_getRequestToken()
    {
        $client = $this->getClient('consumer');

        $requestTokenUrl = $this->getLocalServerUrl() . '/request-token.php';
        $requestToken    = $client->getRequestToken($requestTokenUrl, 'http://example.com/');
        $this->assertArrayHasKey('oauth_token', $requestToken);
        $this->assertEquals('request-token', $requestToken['oauth_token']);
        $this->assertArrayHasKey('oauth_token_secret', $requestToken);
        $this->assertEquals('request-secret', $requestToken['oauth_token_secret']);
    }

    public function test_getRequestToken_invalid_consumer()
    {
        $this->expectException(OAuthException::class);
        $client = $this->getClient('consumer-invalid');

        $requestTokenUrl = $this->getLocalServerUrl() . '/request-token.php';
        $client->getRequestToken($requestTokenUrl, 'http://example.com/');
    }

    public function test_getRequestToken_throttled_consumer()
    {
        $this->expectException(OAuthException::class);
        $client = $this->getClient('consumer-refused');

        $requestTokenUrl = $this->getLocalServerUrl() . '/request-token.php';
        $client->getRequestToken($requestTokenUrl, 'http://example.com/');
    }

    public function test_getAccessToken()
    {
        $client = $this->getClient('consumer');
        $client->setToken('request-token', static::$tokens['request-tokens']['request-token']);

        $accessTokenUrl = $this->getLocalServerUrl() . '/access-token.php';
        $accessToken    = $client->getAccessToken($accessTokenUrl, null, static::$tokens['request-token-verifier']);
        $this->assertArrayHasKey('oauth_token', $accessToken);
        $this->assertEquals('token', $accessToken['oauth_token']);
        $this->assertArrayHasKey('oauth_token_secret', $accessToken);
        $this->assertEquals('secret', $accessToken['oauth_token_secret']);
    }

    public function test_getAccessToken_invalid_verifier()
    {
        $this->expectException(OAuthException::class);
        $client = $this->getClient('consumer');
        $client->setToken('request-token', static::$tokens['request-tokens']['request-token']);

        $accessTokenUrl = $this->getLocalServerUrl() . '/access-token.php';
        $client->getAccessToken($accessTokenUrl, null, '987654');
    }

    public function test_getAccessToken_missing_verifier()
    {
        $this->expectException(OAuthException::class);
        $client = $this->getClient('consumer');
        $client->setToken('request-token', static::$tokens['request-tokens']['request-token']);

        $accessTokenUrl = $this->getLocalServerUrl() . '/access-token.php';
        $client->getAccessToken($accessTokenUrl);
    }

    public function test_getAccessToken_expired_token()
    {
        $this->expectException(OAuthException::class);
        $client = $this->getClient('consumer');
        $client->setToken('request-token-expired', static::$tokens['request-tokens']['request-token-expired']);

        $accessTokenUrl = $this->getLocalServerUrl() . '/access-token.php';
        $client->getAccessToken($accessTokenUrl, null, static::$tokens['request-token-verifier']);
    }

    public function test_getAccessToken_invalid_token()
    {
        $this->expectException(OAuthException::class);
        $client = $this->getClient('consumer');
        $client->setToken('request-token-invalid', static::$tokens['request-tokens']['request-token-invalid']);

        $accessTokenUrl = $this->getLocalServerUrl() . '/access-token.php';
        $client->getAccessToken($accessTokenUrl, null, static::$tokens['request-token-verifier']);
    }

    /**
     * Performs a simple GET request, may fail if OAuthProvider has issues and doesn't provide the correct responses
     * from the server
     */
    public function test_fetch_get()
    {
        $client = $this->getClient('consumer');
        $client->setToken('token', static::$tokens['access-tokens']['token']);

        $requestUrl = $this->getLocalServerUrl() . '/request.php';
        $client->fetch($requestUrl, null, OAUTH_HTTP_METHOD_GET);

        // Check info for expected keys
        $responseInfo = $client->getLastResponseInfo();
        $this->normalizeResponseInfo($responseInfo);
        $this->assertTrue(is_array($responseInfo), 'ResponseInfo should be an array');
        $this->assertArrayHasKey('url', $responseInfo);
        $this->assertArrayHasKey('content_type', $responseInfo);
        $this->assertArrayHasKey('http_code', $responseInfo);
        $this->assertArrayHasKey('size_download', $responseInfo);
        $this->assertArrayHasKey('size_upload', $responseInfo);

        // Parse and check headers for expected values
        $responseHeaders = $client->getLastResponseHeaders();
        $headers         = $this->parseResponseHeaders($responseHeaders);
        $this->assertArrayHasKey('host', $headers);
        $this->assertArrayHasKey('date', $headers);
        $this->assertArrayHasKey('connection', $headers);
        $this->assertArrayHasKey('x-powered-by', $headers);

        // Check response for expected keys
        $raw  = $client->getLastResponse();
        $data = json_decode($raw, true);
        $this->assertTrue(is_array($data),
            'Response body was not valid JSON. Response was ' . number_format(strlen($raw)) . ' bytes of "' . $responseInfo['content_type'] . '"');
        $this->assertArrayHasKey('get', $data);
        $this->assertArrayHasKey('post', $data);
        $this->assertArrayHasKey('input', $data);
        $this->assertEmpty($data['get']);
        $this->assertEmpty($data['post']);
        $this->assertEmpty($data['input']);
    }

    /**
     * @depends test_fetch_get
     */
    public function test_fetch_only_url()
    {
        $client = $this->getClient('consumer');
        $client->setToken('token', static::$tokens['access-tokens']['token']);

        $requestUrl = $this->getLocalServerUrl() . '/request.php';
        $client->fetch($requestUrl);

        $raw  = $client->getLastResponse();
        $data = json_decode($raw, true);
        $this->assertTrue(is_array($data));
    }

    public function provideStatusCodes()
    {
        return [
            'OK'                => [200],
            'Created'           => [201],
            'Moved'             => [301],
            'Moved Permanently' => [302],
            'Bad Request'       => [400],
            'Unauthorized'      => [401],
            'Not Found'         => [404],
            'Server Error'      => [500],
        ];
    }

    /**
     * @dataProvider provideStatusCodes
     * @depends      test_fetch_get
     */
    public function test_fetch_get_with_status($status)
    {
        $client = $this->getClient('consumer');
        $client->setToken('token', static::$tokens['access-tokens']['token']);

        // This will test redirect codes, so don't try to follow them!
        $client->disableRedirects();
        $requestUrl = $this->getLocalServerUrl() . '/request.php?status=' . $status;

        try {
            $client->fetch($requestUrl, null, OAUTH_HTTP_METHOD_GET);
        } catch (OAuthException $e) {
            $this->assertEquals($status, $e->getCode(), 'Unexpected HTTP status');

            return;
        }

        $info = $client->getLastResponseInfo();
        $this->normalizeResponseInfo($info);
        $this->assertEquals($status, $info['http_code'], 'Unexpected HTTP status');
    }

    /**
     * @depends test_fetch_get
     */
    public function test_fetch_get_with_params()
    {
        $client = $this->getClient('consumer');
        $client->setToken('token', static::$tokens['access-tokens']['token']);

        $requestUrl = $this->getLocalServerUrl() . '/request.php?bar=baz';
        $client->fetch($requestUrl, ['foo' => 'bar'], OAUTH_HTTP_METHOD_GET);

        $raw  = $client->getLastResponse();
        $data = json_decode($raw, true);
        $get  = $data['get'];
        $this->assertArrayHasKey('foo', $get);
        $this->assertEquals('bar', $get['foo']);
        $this->assertArrayHasKey('bar', $get);
        $this->assertEquals('baz', $get['bar']);
    }

    function provideRequestEngines() {
        return [
            'ext-curl' => [
                null // OAUTH_REQENGINE_CURL isn't defined in PECL extension
            ],
            'php streams' => [
                OAUTH_REQENGINE_STREAMS
            ],
        ];
    }

    /**
     * @depends test_fetch_get
     * @dataProvider provideRequestEngines
     */
    public function test_fetch_using_mixed_params($engine)
    {
        $client = $this->getClient('consumer');
        $client->setToken('token', static::$tokens['access-tokens']['token']);
        if ($engine) {
            $client->setRequestEngine($engine);
        }

        $requestUrl = $this->getLocalServerUrl() . '/request.php?bar=baz';
        $client->fetch($requestUrl, ['foo' => 'bar'], OAUTH_HTTP_METHOD_GET);

        $raw  = $client->getLastResponse();
        $data = json_decode($raw, true);
        $this->assertTrue(is_array($data), 'Unable to parse JSON from response');
        $this->assertArrayHasKey('get', $data);

        // Check the passed values
        $get  = $data['get'];
        $this->assertArrayHasKey('foo', $get);
        $this->assertEquals('bar', $get['foo']);
        $this->assertArrayHasKey('bar', $get);
        $this->assertEquals('baz', $get['bar']);
    }

    /**
     * @depends test_fetch_get
     */
    public function test_fetch_post_with_params()
    {
        $client = $this->getClient('consumer');
        $client->setToken('token', static::$tokens['access-tokens']['token']);

        $requestUrl = $this->getLocalServerUrl() . '/request.php?bar=baz';
        $client->fetch($requestUrl, ['foo' => 'bar'], OAUTH_HTTP_METHOD_POST);

        $raw  = $client->getLastResponse();
        $data = json_decode($raw, true);
        $this->assertArrayHasKey('foo', $data['post']);
        $this->assertEquals('bar', $data['post']['foo']);
        $this->assertArrayHasKey('bar', $data['get']);
        $this->assertEquals('baz', $data['get']['bar']);
    }

    /**
     * @depends test_fetch_get
     */
    public function test_fetch_put_a_file()
    {
        $client = $this->getClient('consumer');
        $client->setToken('token', static::$tokens['access-tokens']['token']);

        $data       = [
            'foo' => 'bar',
            'bar' => 'baz',
        ];
        $json       = json_encode($data);
        $headers    = [
            'Content-Type'   => 'application/json',
            'Content-Length' => strlen($json),
            'Content-MD5'    => md5($json),
        ];
        $requestUrl = $this->getLocalServerUrl() . '/request.php';
        $client->fetch($requestUrl, $json, OAUTH_HTTP_METHOD_PUT, $headers);

        $response = $client->getLastResponse();
        $data     = json_decode($response, true);
        $this->assertEquals($json, $data['input']);
    }

    /**
     * In this case, the OAuth parameters will be appended to the request body which will not be parsed correctly
     */
    public function test_fetch_post_odd_request()
    {
        $this->expectException(OAuthException::class);
        $consumer = 'consumer';
        $token    = 'token';
        $client   = new OAuth($consumer, static::$tokens['consumer-tokens'][$consumer], OAUTH_SIG_METHOD_HMACSHA1,
            OAUTH_AUTH_TYPE_FORM);
        $client->setToken($token, static::$tokens['access-tokens'][$token]);
        $client->fetch($this->getLocalServerUrl() . '/request.php', '{}', OAUTH_HTTP_METHOD_POST,
            ['Content-type' => 'application/json']);
    }

    /**
     * In this case, the OAuth parameters will be also be appended to the request body, but the properly encoded
     * parameters will parse correctly
     */
    public function test_fetch_post_odd_request_two()
    {
        $this->expectException(OAuthException::class);
        $consumer = 'consumer';
        $token    = 'token';
        $client   = new OAuth($consumer, static::$tokens['consumer-tokens'][$consumer], OAUTH_SIG_METHOD_HMACSHA1,
            OAUTH_AUTH_TYPE_FORM);
        $client->setToken($token, static::$tokens['access-tokens'][$token]);
        $client->fetch($this->getLocalServerUrl() . '/request.php', 'foo=bar&bar=baz', OAUTH_HTTP_METHOD_POST);
    }


    /**
     * @depends test_fetch_get
     */
    public function test_fetch_get_expecting_error()
    {
        $client = $this->getClient('consumer');
        $client->setToken('token', 'not-the-actual-secret');

        $e   = null;
        $url = $this->getLocalServerUrl() . '/request.php';
        try {
            $client->fetch($url);
        } catch (OAuthException $e) {
        }

        $this->assertInstanceOf(OAuthException::class, $e);
        $this->assertNull($e->debugInfo, 'Debug info should be null by default');
        $this->assertEquals($client->debugInfo, $e->debugInfo, 'Client and exception debugInfo differed');

        $this->assertEquals('OAuthException: 64: Signatures do not match', $e->lastResponse);
        $this->assertEquals($client->getLastResponse(), $e->lastResponse, 'Client and exception responses differed');
    }

    /**
     * @depends test_fetch_get
     */
    public function test_fetch_get_expecting_error_with_debug_enabled()
    {
        $client = $this->getClient('consumer');
        $client->setToken('token', 'not-the-actual-secret');
        $client->enableDebug();

        $e   = null;
        $url = $this->getLocalServerUrl() . '/request.php';
        try {
            $client->fetch($url);
        } catch (OAuthException $e) {
        }

        $this->assertInstanceOf(OAuthException::class, $e);
        $this->assertTrue(is_array($e->debugInfo), 'debugInfo property should be an array');
        $this->assertArrayHasKey('sbs', $e->debugInfo);
        $this->assertArrayHasKey('headers_sent', $e->debugInfo);
        $this->assertArrayHasKey('headers_recv', $e->debugInfo);
        $this->assertArrayHasKey('body_recv', $e->debugInfo);
        $this->assertEquals($client->debugInfo, $e->debugInfo, 'Client and exception debug info differed');

        $this->assertEquals('OAuthException: 64: Signatures do not match', $e->lastResponse);
        $this->assertEquals($client->getLastResponse(), $e->lastResponse, 'Client and exception responses differed');
    }

    /**
     * @param string $consumer
     *
     * @return OAuth
     */
    private function getClient($consumer)
    {
        return new OAuth($consumer, static::$tokens['consumer-tokens'][$consumer]);
    }

    /**
     * Remove the '\u0000' at the end of each key
     *
     * @param $responseInfo
     */
    private function normalizeResponseInfo(&$responseInfo)
    {
        if (!is_array($responseInfo)) {
            return;
        }

        foreach ($responseInfo as $key => $value) {
            unset($responseInfo[$key]);
            $responseInfo[trim($key)] = trim($value);
        }
    }

    /**
     * Break up the HTTP header into key/value pairs
     *
     * @param string $responseHeader
     *
     * @return array
     */
    private function parseResponseHeaders($responseHeader)
    {
        $headerLines = explode("\n", $responseHeader);
        $headers     = [];
        foreach ($headerLines as $header) {
            $header = trim($header);
            $pieces = explode(': ', $header);
            if (count($pieces) > 1) {
                $name                       = trim(array_shift($pieces));
                $headers[strtolower($name)] = trim(implode(': ', $pieces));
            }
        }

        return $headers;
    }
}