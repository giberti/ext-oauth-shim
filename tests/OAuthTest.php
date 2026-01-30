<?php

use PHPUnit\Framework\TestCase;

class OAuthTest extends TestCase
{

    /**
     * Holds the assorted test tokens and secrets the client and server will need
     *
     * @var array
     */
    public static $tokens;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        $tokenFile = __DIR__ . '/localhost/tokens.php';
        if (!file_exists($tokenFile)) {
            trigger_error('Unable to read token file');
        }
        static::$tokens = include $tokenFile;
    }

    public function test_create_without_consumer_key()
    {
        $this->expectException(OAuthException::class);
        new OAuth();
    }

    public function test_create_without_consumer_key_message()
    {
        $e = null;
        try {
            new OAuth();
            // catch the most generic class
        } catch (Throwable $e) {
        }

        $this->assertInstanceOf(OAuthException::class, $e);
        $this->assertEquals('The consumer key cannot be empty', $e->getMessage());
        $this->assertEquals(-1, $e->getCode());
    }

    public function test_create_without_consumer_secret()
    {
        $this->expectException(OAuthException::class);
        new OAuth('consumer');
    }

    public function test_create_without_consumer_key_secret_message()
    {
        $e = null;
        try {
            new OAuth('consumer');
            // catch the most generic class
        } catch (Throwable $e) {
        }

        $this->assertInstanceOf(OAuthException::class, $e);
        $this->assertEquals('The consumer secret cannot be empty', $e->getMessage());
        $this->assertEquals(-1, $e->getCode());
    }

    public function test_set_version()
    {
        $o = new OAuth('client', 'secret');
        $this->assertTrue($o->setVersion('1.0'), 'Setting the version should return true');

        try {
            $this->assertTrue($o->setVersion(''), 'Setting the version should return true');
        } catch (Throwable $e) {
            $this->assertInstanceOf(OAuthException::class, $e);
            $this->assertEquals('Invalid version', $e->getMessage());
            $this->assertEquals(503, $e->getCode());
        }
    }

    public function test_create_with_signature_method()
    {
        $o = new OAuth('consumer', 'secret', OAUTH_SIG_METHOD_HMACSHA1);
        $this->assertInstanceOf(OAuth::class, $o);

        $o = new OAuth('consumer', 'secret', 'not-a-valid-signature-method');
        $this->assertInstanceOf(OAuth::class, $o);
    }

    public function test_create_with_auth_type()
    {
        $o = new OAuth('consumer', 'secret', OAUTH_SIG_METHOD_HMACSHA1, OAUTH_AUTH_TYPE_URI);
        $this->assertInstanceOf(OAuth::class, $o);
    }

    public function test_setAuthType()
    {
        $o = new OAuth('consumer', 'secret');
        $this->assertInstanceOf(OAuth::class, $o);
        $this->assertTrue($o->setAuthType(OAUTH_AUTH_TYPE_FORM));

        try {
            $o->setAuthType(9999);
        } catch (Throwable $e) {
            $this->assertInstanceOf(OAuthException::class, $e);
            $this->assertEquals('Invalid auth type', $e->getMessage());
            $this->assertEquals(503, $e->getCode());
        }
    }

    public function test_setRSACertificate()
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL is required for RSA signing');
        }

        $o = new OAuth('consumer', 'secret', OAUTH_SIG_METHOD_RSASHA1);
        $this->assertTrue($o->setRSACertificate(file_get_contents(__DIR__ . '/rsa/test.pem')));

        try {
            $o->setRSACertificate('asdf');
        } catch (Throwable $e) {
            $this->assertInstanceOf(OAuthException::class, $e);
            $this->assertEquals('Could not parse RSA certificate', $e->getMessage());
            $this->assertEquals(503, $e->getCode());
        }
    }

    public function test_enable_disable_debug_property()
    {
        $o = new OAuth('consumer', 'secret');
        $this->assertFalse($o->debug, 'Debug should default to false');
        $o->enableDebug();
        $this->assertTrue($o->debug, 'Debug should be enabled after calling enableDebug()');
        $o->disableDebug();
        $this->assertFalse($o->debug, 'Debug should be disabled after calling disableDebug()');
        $o->debug = true;
        $this->assertTrue($o->debug, 'Debug should be enabled after setting property to true');
        $o->debug = false;
        $this->assertFalse($o->debug, 'Debug should be disabled after setting property to false');
    }

    public function test_enable_disable_ssl_check_property()
    {
        $o = new OAuth('consumer', 'secret');
        $this->assertTrue((bool)$o->sslChecks, 'SSL checks should be enabled by default');
        $o->disableSSLChecks();
        $this->assertFalse((bool)$o->sslChecks, 'SSL checks should be disabled after calling disableSSLChecks()');
        $o->enableSSLChecks();
        $this->assertTrue((bool)$o->sslChecks, 'SSL checks should be enabled after calling enableSSLChecks()');
        $o->disableSSLChecks();
        $this->assertFalse((bool)$o->sslChecks, 'SSL checks should be disabled after calling disableSSLChecks()');
        $o->sslChecks = 1;
        $this->assertTrue((bool)$o->sslChecks, 'SSL checks should be disabled after setting property to false');
        $o->sslChecks = 0;
        $this->assertFalse((bool)$o->sslChecks, 'SSL checks should be disabled after setting property to false');
    }

    /**
     * @depends test_enable_disable_ssl_check_property
     */
    public function test_setSSLChecks()
    {
        $o = new OAuth('consumer', 'secret');
        $this->assertEquals(OAUTH_SSLCHECK_BOTH, $o->sslChecks, 'Checks should be enabled');

        $o->disableSSLChecks();
        $this->assertEquals(OAUTH_SSLCHECK_NONE, $o->sslChecks, 'Checks should be disabled');
        $this->assertTrue($o->setSSLChecks(OAUTH_SSLCHECK_HOST), 'Setting should return true');
        $this->assertEquals(OAUTH_SSLCHECK_HOST, $o->sslChecks);

        $o->disableSSLChecks();
        $this->assertEquals(OAUTH_SSLCHECK_NONE, $o->sslChecks, 'Checks should be disabled');
        $this->assertTrue($o->setSSLChecks(OAUTH_SSLCHECK_PEER), 'Setting should return true');
        $this->assertEquals(OAUTH_SSLCHECK_PEER, $o->sslChecks);

        $o->disableSSLChecks();
        $this->assertEquals(OAUTH_SSLCHECK_NONE, $o->sslChecks, 'Checks should be disabled');
        $this->assertTrue($o->setSSLChecks(OAUTH_SSLCHECK_HOST), 'Setting should return true');
        $this->assertEquals(OAUTH_SSLCHECK_HOST, $o->sslChecks);
        $this->assertTrue($o->setSSLChecks(OAUTH_SSLCHECK_PEER), 'Setting should return true');
        $this->assertEquals(OAUTH_SSLCHECK_PEER, $o->sslChecks);
    }

    public function test_setNonce()
    {
        $o = new OAuth('consumer', 'secret');
        $this->assertTrue($o->setNonce('nonce'));

        $e = null;
        try {
            $o->setNonce('');
        } catch (Throwable $e) {
        }

        $this->assertInstanceOf(OAuthException::class, $e);
        $this->assertEquals('Invalid nonce', $e->getMessage());
        $this->assertEquals(503, $e->getCode());
    }

    public function test_setTimestamp()
    {
        $o = new OAuth('consumer', 'secret');
        $this->assertTrue($o->setTimestamp(time()));

        $e = null;
        try {
            $o->setTimestamp('');
        } catch (Throwable $e) {
        }
        $this->assertInstanceOf(OAuthException::class, $e);
        $this->assertEquals('Invalid timestamp', $e->getMessage());
        $this->assertEquals(503, $e->getCode());
    }

    public function test_setToken()
    {
        $o = new OAuth('consumer', 'secret');
        $this->assertTrue($o->setToken(null, null));
    }

    public function test_setRequestEngine()
    {
        $o = new OAuth('consumer', 'secret');
        $o->setRequestEngine(OAUTH_REQENGINE_STREAMS);

        $e = null;
        try {
            $o->setRequestEngine(9999);
        } catch (Throwable $e) {
        }
        $this->assertInstanceOf(OAuthException::class, $e);
        $this->assertEquals('Invalid request engine specified', $e->getMessage());
        $this->assertEquals(503, $e->getCode());
    }

    public function test_setCAPath_and_getCAPath()
    {
        $o = new OAuth('consumer', 'secret');
        $this->assertTrue($o->setCAPath('path', 'info'));
        $v = $o->getCAPath();
        $this->assertTrue(is_array($v));
        $this->assertArrayHasKey('ca_info', $v);
        $this->assertArrayHasKey('ca_path', $v);
        $this->assertEquals('info', $v['ca_info']);
        $this->assertEquals('path', $v['ca_path']);
    }

    public function test_generateSignature_fails_with_invalid_url()
    {
        $this->expectException(OAuthException::class);
        $o = new OAuth('consumer', 'secret');
        $o->generateSignature('GET', 'invalid-url', []);
    }


    public static function provide_signatureTestData()
    {
        return [
            'simple get'                 => [
                'get',
                'http://example.com/',
                [],
                '3nnfYjm846E1YI/24wxD3IuplI4=',
                'cvdtbUtWnIm7vRuuvtHxhRUHn0C5DNSACxkA6tLcE2g=',
                'secret&secret',
            ],
            'complex url get'            => [
                'get',
                'http://::1:8888/~foo!bar?foo=bar',
                ['p1' => 'p1', 'p2' => 'p2'],
                '82RqAa3gYadI3uKswhdcg6NHloE=',
                'C2ZSkeNhon7MCB/SF0ELf8/7EBfD8wBv0IO5Y665mSM=',
                'secret&secret',
            ],
            'mixed parameter source get' => [
                'get',
                'http://example.com/?p2=p2',
                ['p1' => 'p1', 'p3' => 'p3'],
                'RAolrPZCU4dosFXHu95UFgkMUxY=',
                'kTWOPD/wPM+drs3mz04WcY2iPvLzDCbBBpp9oU1ZGcc=',
                'secret&secret',
            ],
            'conflicting parameters get' => [
                'get',
                'http://example.com/?p1=qs1&p2=qs2',
                ['p1' => 'ep1', 'p2' => 'ep2'],
                'h/9k13VCF6Gk/B5Zxq+oYAb1oO8=',
                'bsaeTrVcoahESdP5zMV3G42hhemUaCQslu0j5v4uqnM=',
                'secret&secret',
            ],
            'simple post'                => [
                'post',
                'http://example.com/',
                ['a' => 'a', 'b' => 'b'],
                'EylqVUaucGp5P88F6HMr+VA5jBM=',
                '3IWGftWgxOO4eq+XzagzhBw1R8nZ0JpRBfxf8B5ciZg=',
                'secret&secret',
            ],
            'json body post'             => [
                'post',
                'http://example.com/',
                json_encode(['a' => 'a', 'b' => 'b']),
                'uI+/hIyE4DAL2mtOMXy0Bzvysgk=',
                'OmWZMQdEB+5SKWsySOCJV4SdYonyXuT7sfBTxLNa5k4=',
                'secret&secret',
            ],
            'post with special chars'    => [
                'post',
                'http://example.com/',
                [
                    'a' => '~!@#$%^&*()_+',
                    'b' => '`1234567890-=\'',
                    'c' => '{}|[]\\',
                    'd' => ':";\'',
                    'e' => '<>?,./',
                    'f' => "\t\n\r",
                ],
                'ZZQSqXLaZKcV4+wPzqF1Xtp0dQ8=',
                's2Vicy69glsIElY9PIhqbLM30sn1VF5YY/UyYcHF+pU=',
                'secret&secret',
            ],
        ];
    }

    /**
     * @dataProvider provide_signatureTestData
     *
     * @param $method
     * @param $uri
     * @param $params
     * @param $sha1Signature
     * @param $sha256Signature
     * @param $plaintextSignature
     */
    public function test_signatureGeneration(
        $method,
        $uri,
        $params,
        $sha1Signature,
        $sha256Signature,
        $plaintextSignature
    ) {
        $clientSha1      = $this->getConfiguredClient(OAUTH_SIG_METHOD_HMACSHA1);
        $clientSha256    = $this->getConfiguredClient(OAUTH_SIG_METHOD_HMACSHA256);
        $clientPlaintext = $this->getConfiguredClient(OAUTH_SIG_METHOD_PLAINTEXT);

        $this->assertEquals($sha1Signature, $clientSha1->generateSignature($method, $uri, $params));
        $this->assertEquals($sha256Signature, $clientSha256->generateSignature($method, $uri, $params));
        $this->assertEquals($plaintextSignature, $clientPlaintext->generateSignature($method, $uri, $params));
    }

    public function test_rsaSignatureGeneration()
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL is required for RSA signing');
        }

        $rsaClient = $this->getConfiguredClient(OAUTH_SIG_METHOD_RSASHA1);
        $rsaClient->setRSACertificate(file_get_contents(__DIR__ . '/rsa/test.pem'));

        $expectedSignature = 'sfiNa7xGGSy91A3Na9UY1yh0cWBoAgTPkNnjilD2/B4EIyHDp7L0Hbzme1C0Ue4F/KMm4s+khevCH+NP+MDpJQucWPu3vkO9J8R0BlNIzJ3poE4c8AxOJXsp0a4iGPZ81IZL+23+M2TiSEz4sRDhF2j0Eer+sumYrXj7HDgtC/6qPWq9Jnbjwi52LXHyEnbEKVJQUpcqCbHT12iPV7wFhma8emOyCFNgDYoc3jwi9SZ5wvrVe0vjYrAsDrnSZCMueucVnpfAMwSJQiWiJ/gfMFcTaUQyKnTnBKPqQ51/HemrhDdm+/VFDpxMm7Q771/Ut+XyqXMTwvOh5e8kclyt0g==';
        $this->assertEquals($expectedSignature,
            $rsaClient->generateSignature(OAUTH_HTTP_METHOD_GET, 'https://example.com/request-token', []));
    }

    /**
     * @depends test_signatureGeneration
     */
    public function test_getRequestHeader()
    {
        $data      = self::provide_signatureTestData()['simple get'];
        $method    = $data[0];
        $url       = $data[1];
        $params    = $data[2];
        $signature = $data[3];
        $client    = $this->getConfiguredClient(OAUTH_SIG_METHOD_HMACSHA1);

        $keyValuePairs = [
            'oauth_callback="http://example.com/"'                  => false,
            'oauth_consumer_key="consumer"'                         => true,
            'oauth_signature_method="HMAC-SHA1"'                    => true,
            'oauth_nonce="nonce"'                                   => true,
            'oauth_timestamp="2"'                                   => true,
            'oauth_version="1.0"'                                   => true,
            'oauth_token="token"'                                   => true,
            'oauth_signature="' . oauth_urlencode($signature) . '"' => true,
        ];

        $generated = $client->getRequestHeader($method, $url, $params);
        foreach ($keyValuePairs as $pair => $expected) {
            if ($expected) {
                $this->assertGreaterThan(0, strpos($generated, $pair), "Did not find {$pair} in the header");
            } else {
                $this->assertFalse(strpos($generated, $pair), "Found unexpected {$pair} in the header");
            }
        }
    }

    /**
     * @param $signatureMethod
     *
     * @return OAuth
     */
    private function getConfiguredClient($signatureMethod)
    {
        $client = new OAuth('consumer', static::$tokens['consumer-tokens']['consumer'], $signatureMethod);
        $client->setToken('token', static::$tokens['access-tokens']['token']);
        // Use a known nonce, timestamp and version
        $client->setNonce('nonce');
        $client->setTimestamp(2);
        $client->setVersion('1.0');

        return $client;
    }
}