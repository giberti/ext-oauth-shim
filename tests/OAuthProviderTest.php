<?php

use PHPUnit\Framework\TestCase;

class OAuthProviderTest extends TestCase {

    public $server;

    public function setUp()
    {
        parent::setUp();

        $this->server = $_SERVER;
    }

    public function tearDown()
    {
        parent::tearDown();

        if ($this->server) {
            $_SERVER = $this->server;
            $this->server = null;
        }
    }

    /**
     * Test a simple, known good request can be instantiated and resolved
     */
    public function test_constructor()
    {
        $params = [
            'oauth_consumer_key'     => 'consumer',
            'oauth_nonce'            => 'nonce',
            'oauth_token'            => 'token',
            'oauth_timestamp'        => 2,
            'oauth_version'          => '1.0',
            'oauth_signature'        => '3nnfYjm846E1YI/24wxD3IuplI4=',
            'oauth_signature_method' => 'HMAC-SHA1',
        ];

        // Create the provider
        $provider = new OAuthProvider($params);
        $this->assertInstanceOf(OAuthProvider::class, $provider);

        // Add handlers
        $provider->consumerHandler(function($provider) {
            $provider->consumer_secret = 'secret';
            return OAUTH_OK;
        });
        $provider->tokenHandler(function($provider) {
            $provider->token_secret = 'secret';
            return OAUTH_OK;
        });
        $provider->timestampNonceHandler(function() { return OAUTH_OK; });

        // Check the request
        $provider->checkOAuthRequest('http://example.com/', 'get');

        // Assert values are expected
        $this->assertEquals($params['oauth_consumer_key'], $provider->consumer_key);
        $this->assertEquals($params['oauth_token'], $provider->token);
        $this->assertEquals($params['oauth_signature'], $provider->signature);
    }

}