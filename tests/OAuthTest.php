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

    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();
        $tokenFile = __DIR__ . '/localhost/tokens.php';
        if (!file_exists($tokenFile)) {
            trigger_error('Unable to read token file');
        }
        static::$tokens = include $tokenFile;
    }


    public function provide_signatureTestData()
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
    public function test_signatureGeneration($method, $uri, $params, $sha1Signature, $sha256Signature, $plaintextSignature)
    {
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