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
        $docRoot = __DIR__ . '/localhost';
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
        $requestToken  = $client->getRequestToken($requestTokenUrl, 'http://example.com/');
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
        $accessToken = $client->getAccessToken($accessTokenUrl, null, static::$tokens['request-token-verifier']);
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

    public function test_fetch_get() {
        $client = $this->getClient('consumer');
        $client->setToken('token', static::$tokens['access-tokens']['token']);

        $requestUrl = $this->getLocalServerUrl() . '/request.php';
        $client->fetch($requestUrl, null, OAUTH_HTTP_METHOD_GET);

        // Check info for expected keys
        $responseInfo = $client->getLastResponseInfo();
        foreach ($responseInfo as $key => $value) {
            // Remove the '\u0000' at the end of each key
            unset($responseInfo[$key]);
            $responseInfo[trim($key)] = trim($value);
        }
        $this->assertTrue(is_array($responseInfo));
        $this->assertArrayHasKey('url', $responseInfo);
        $this->assertArrayHasKey('http_code', $responseInfo);
        $this->assertArrayHasKey('size_download', $responseInfo);
        $this->assertArrayHasKey('size_upload', $responseInfo);

        // Parse and check headers for expected values
        $responseHeaders = $client->getLastResponseHeaders();
        $headerLines = explode("\n", $responseHeaders);
        $headers = [];
        foreach ($headerLines as $header) {
            $header = trim($header);
            $pieces = explode(': ', $header);
            if (count($pieces) > 1) {
                $name = trim(array_shift($pieces));
                $headers[strtolower($name)] = trim(implode(': ', $pieces));
            }
        }
        $this->assertArrayHasKey('host', $headers);
        $this->assertArrayHasKey('date', $headers);
        $this->assertArrayHasKey('connection', $headers);
        $this->assertArrayHasKey('x-powered-by', $headers);

        // Check response for expected keys
        $raw = $client->getLastResponse();
        $data = json_decode($raw, true);
        $this->assertTrue(is_array($data));
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
    public function test_fetch_get_with_params() {
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

    /**
     * @depends test_fetch_get
     */
    public function test_fetch_post_with_params() {
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
     * @param string $consumer
     *
     * @return OAuth
     */
    private function getClient($consumer) {
        return new OAuth($consumer, static::$tokens['consumer-tokens'][$consumer]);
    }
}