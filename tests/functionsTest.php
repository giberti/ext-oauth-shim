<?php

use PHPUnit\Framework\Error\Warning;
use PHPUnit\Framework\TestCase;

class FunctionsTest extends TestCase
{

    public function provide_oauth_get_sbs()
    {
        return [
            'basic string generation'                  => [
                'method',
                'http://example.com/',
                [], // params
                'method&http%3A%2F%2Fexample.com%2F&',
            ],
            'method case preserved'                    => [
                'MeThOd',
                'http://example.com/',
                [], // params
                'MeThOd&http%3A%2F%2Fexample.com%2F&',
            ],
            'scheme and host lower case, but not path' => [
                'method',
                'HTTP://EXAMPLE.COM/FOO.PHP',
                [],
                'method&http%3A%2F%2Fexample.com%2FFOO.PHP&',
            ],
            'specified port numbers work'              => [
                'method',
                'http://example.com:8888/',
                [],
                'method&http%3A%2F%2Fexample.com%3A8888%2F&',
            ],
            'ipv4 host names work'                     => [
                'method',
                'http://127.0.0.1/',
                [],
                'method&http%3A%2F%2F127.0.0.1%2F&',
            ],
            'ipv4 host names with a port work'         => [
                'method',
                'http://127.0.0.1:8888/',
                [],
                'method&http%3A%2F%2F127.0.0.1%3A8888%2F&',
            ],
            'ipv6 host names work'                     => [
                'method',
                'http://::1/',
                [],
                'method&http%3A%2F%2F%3A%3A1%2F&',
            ],
            'ipv6 host names with a port work'         => [
                'method',
                'http://::1:8888/',
                [],
                'method&http%3A%2F%2F%3A%3A1%3A8888%2F&',
            ],
            'params encode properly'                   => [
                'method',
                'http://example.com/',
                [
                    'k1' => 'v1',
                    'k2' => '$1',
                    'k3' => '{}',
                    'k4' => '%',
                ],
                'method&http%3A%2F%2Fexample.com%2F&k1%3Dv1%26k2%3D%25241%26k3%3D%257B%257D%26k4%3D%2525',
            ],
            'params sort correctly'                    => [
                'method',
                'http://example.com/',
                [
                    'k4' => '%',
                    'k2' => '$1',
                    'k3' => '{}',
                    'k1' => 'v1',
                ],
                'method&http%3A%2F%2Fexample.com%2F&k1%3Dv1%26k2%3D%25241%26k3%3D%257B%257D%26k4%3D%2525',
            ],
            'mixed parameters and query string'        => [
                'method',
                'http://example.com/?k1=v1',
                [
                    'k2' => 'k2',
                ],
                'method&http%3A%2F%2Fexample.com%2F&k1%3Dv1%26k2%3Dk2',
            ],
            'parameter precedence'                     => [
                'method',
                'http://example.com/?k1=qs1&k2=qs2',
                [
                    'k1' => 'ep1',
                    'k2' => 'ep2',
                ],
                'method&http%3A%2F%2Fexample.com%2F&k1%3Dqs1%26k2%3Dqs2',
            ],
            'sensitive parameters'                     => [
                'method',
                'http://example.com/?k1=v1',
                [
                    'oauth_consumer_secret' => 'secret',
                    'oauth_signature'       => 'asdf',
                    'oauth_token_secret'    => 'secret',
                ],
                'method&http%3A%2F%2Fexample.com%2F&k1%3Dv1%26oauth_consumer_secret%3Dsecret%26oauth_token_secret%3Dsecret',
            ],
        ];
    }

    /**
     * Checks that the oauth_get_sbs function behaves as expected
     *
     * @dataProvider provide_oauth_get_sbs
     */
    public function test_oauth_get_sbs($method, $uri, $params, $expected)
    {
        $actual = oauth_get_sbs($method, $uri, $params);
        $this->assertEquals($expected, $actual, 'Incorrect signature base string');
    }

    public function provide_invalid_urls()
    {
        return [
            'Missing path'        => ['http://example.com'],
            'Relative path'       => ['/api/example'],
            'Schema-less url'     => ['//example.com/'],
            'Schema-less url two' => ['://example.com/'],
        ];
    }

    /**
     * @dataProvider provide_invalid_urls
     */
    public function test_oauth_get_sbs_fails_invalid_urls($url)
    {
        $this->expectException(OAuthException::class);
        oauth_get_sbs('method', $url, []);
    }

    public function provide_oauth_get_sbs_invalid_params()
    {
        return [
            'missing method' => [
                null,
                'http://example.com/',
                [],
            ],
            'missing url' => [
                'method',
                null,
                [],
            ],
        ];
    }

    /**
     * @dataProvider provide_oauth_get_sbs_invalid_params
     */
    public function test_oauth_get_sbs_empty_parameter_errors($method, $url, $params)
    {
        $e = null;
        $returned = null;
        try {
            $returned = oauth_get_sbs($method, $url, $params);
        } catch (Throwable $e) {
        }
        $this->assertInstanceOf(
            Warning::class,
            $e,
            'Expected Warning not raised, got ' . get_class($e) . ' instead'
        );
        $this->assertNull($returned);
    }

    public function provide_oauth_urlencode()
    {
        return [
            'properly encode scheme://host:port'                 => [
                'scheme://example.com:8088/',
                'scheme%3A%2F%2Fexample.com%3A8088%2F',
            ],
            'properly handle tilde, bang, equals, and ampersand' => [
                'http://foo.bar/~baz!baz?foo=bar',
                'http%3A%2F%2Ffoo.bar%2F~baz%21baz%3Ffoo%3Dbar',
            ],
        ];
    }

    /**
     * Checks that the oauth_urlencode function behaves as expected
     *
     * @dataProvider provide_oauth_urlencode
     */
    public function test_oauth_urlencode($uri, $expected)
    {
        $this->assertEquals($expected, oauth_urlencode($uri), 'Incorrect encoding');
    }
}
