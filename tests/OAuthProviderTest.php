<?php

use PHPUnit\Framework\TestCase;

class OAuthProviderTest extends TestCase {

    public ?array $server;

    public function setUp(): void
    {
        parent::setUp();

        $this->server = $_SERVER;
    }

    public function tearDown(): void
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
    public function test_constructor(): void
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
        $provider = $this->createProviderWithParams($params);
        $provider->checkOAuthRequest('http://example.com/', 'get');

        // Assert values are expected
        $this->assertEquals($params['oauth_consumer_key'], $provider->consumer_key);
        $this->assertEquals($params['oauth_token'], $provider->token);
        $this->assertEquals($params['oauth_signature'], $provider->signature);
    }

    /**
     * Adds 'foo' to the request and validates it's there
     *
     * @depends test_constructor
     */
    public function test_addRequiredParameter(): void
    {
        $params = [
            'oauth_consumer_key'     => 'consumer',
            'oauth_nonce'            => 'nonce',
            'oauth_token'            => 'token',
            'oauth_timestamp'        => 2,
            'oauth_version'          => '1.0',
            'oauth_signature'        => '8B9t2wK6hbVG8w+ydnN4coZ3RY4=',
            'oauth_signature_method' => 'HMAC-SHA1',
            'foo'                    => true,
        ];

        $provider = $this->createProviderWithParams($params);
        $provider->addRequiredParameter('foo');
        $provider->checkOAuthRequest('http://example.com/', 'get');

        // Assert values are expected
        $this->assertEquals($params['oauth_consumer_key'], $provider->consumer_key);
        $this->assertEquals($params['oauth_token'], $provider->token);
        $this->assertEquals($params['oauth_signature'], $provider->signature);
    }

    /**
     * Requires 'foo' but it's not present in the request
     *
     * @depends test_constructor
     */
    public function test_addRequiredParameterMissing(): void
    {
        $params = [
            'oauth_consumer_key'     => 'consumer',
            'oauth_nonce'            => 'nonce',
            'oauth_token'            => 'token',
            'oauth_timestamp'        => 2,
            'oauth_version'          => '1.0',
            'oauth_signature'        => '8B9t2wK6hbVG8w+ydnN4coZ3RY4=',
            'oauth_signature_method' => 'HMAC-SHA1',
        ];

        $e = null;
        $provider = $this->createProviderWithParams($params);
        $provider->addRequiredParameter('foo');
        try {
            $provider->checkOAuthRequest('http://example.com/', 'get');
        } catch (Throwable $e) {}

        $this->assertInstanceOf(OAuthException::class, $e);
        $this->assertEquals(OAUTH_PARAMETER_ABSENT, $e->getCode(), 'Expected parameter absent code');
        $this->assertEquals('Missing required parameters', $e->getMessage());
        $this->assertEquals('foo', $e->additionalInfo, 'Expected to find additional information set on undocumented property');
    }

    /**
     * Make sure we get a reasonable length token back
     */
    public function test_generateToken(): void
    {
        // 2^16 = 65,536
        for ($exp = 1; $exp < 16; $exp++) {
            $bytes = pow(2, $exp);
            $token = OAuthProvider::generateToken($bytes);
            $this->assertEquals($bytes, strlen($token), "Expected {$bytes} byte token");
        }
    }

    /**
     * Make sure we get a reasonable length token back
     */
    public function test_generateTokenError(): void
    {
        $e = null;
        try {
            OAuthProvider::generateToken(0);
        } catch (Throwable $e) {}
        $this->assertInstanceOf(\PHPUnit\Framework\Error\Warning::class, $e);
        $this->assertStringStartsWith('OAuthProvider::generateToken(): Cannot generate token with a size of less than 1 or greater than ', $e->getMessage());
    }

    /**
     * @param array $params Parameters to pass to the constructor
     *
     * @return OAuthProvider
     */
    private function createProviderWithParams($params): \OAuthProvider
    {
        // Create provider
        $provider = new OAuthProvider($params);

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

        return $provider;
    }

}
