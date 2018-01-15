<?php

/**
 * Provides the non-namespaced, non-classed functions provided by PECL OAuth
 * extension
 */

if (extension_loaded('oauth')) {
    return;
}

if (!function_exists('oauth_get_sbs')) {
    /**
     * Generates a Signature Base String according to pecl/oauth.
     *
     * @see http://php.net/manual/en/function.oauth-get-sbs.php
     *
     * @param string $http_method
     * @param string $uri
     * @param array  $request_parameters
     *
     * @return string
     * @throws OAuthException
     */
    function oauth_get_sbs($http_method, $uri, array $request_parameters = [])
    {
        // Validate the request uri values
        $uriPieces = parse_url($uri);
        if (!isset($uriPieces['host']) || !isset($uriPieces['scheme'])) {
            throw new OAuthException('Invalid url when trying to build base signature string');
        }
        if (!isset($uriPieces['path'])) {
            throw new OAuthException('Invalid path (perhaps you only specified the hostname? try adding a slash at the end)');
        }

        // Adjust formatting of scheme & host
        $uriPieces['scheme'] = strtolower($uriPieces['scheme']);
        $uriPieces['host']   = strtolower($uriPieces['host']);

        // Remove the query string
        $get = [];
        if (isset($uriPieces['query'])) {
            $queryString = $uriPieces['query'];
            parse_str($queryString, $get);
            unset($uriPieces['query']);
        };

        // Rebuild the Uri without the query
        if (function_exists('http_build_url')) {
            $uri = http_build_url($uriPieces);
        } else {
            $uri = "{$uriPieces['scheme']}://{$uriPieces['host']}";
            if (isset($uriPieces['port'])) {
                $uri .= ":{$uriPieces['port']}";
            }
            $uri .= "{$uriPieces['path']}";
        }

        // Sort and generate the parameter string
        $request_parameters += $get;
        ksort($request_parameters);
        $parameters = "";
        foreach ($request_parameters as $key => $value) {
            if (strlen($parameters) > 0) {
                $parameters .= '&';
            }
            $parameters .= rawurlencode($key) . '=' . rawurlencode($value);
        }

        // Encode and generate base string
        $http_method = rawurlencode($http_method);
        $uri         = rawurlencode($uri);
        $parameters  = rawurlencode($parameters);

        return "{$http_method}&{$uri}&{$parameters}";
    }
}

if (!function_exists('oauth_urlencode')) {
    /**
     * Encode a URI to RFC 3986
     *
     * @see http://php.net/manual/en/function.oauth-urlencode.php
     *
     * @param $uri
     *
     * @return string
     */
    function oauth_urlencode($uri)
    {
        return rawurlencode($uri);
    }
}
