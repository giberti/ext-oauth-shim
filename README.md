# OAuth Extension Shim

Aims to provides support for `OAuth`, `OAuthException`, and `OAuthProvider` and satisfy the `ext-oauth` requirement for composer packages that require it. This is a work in progress.

**WARNING:** If possible, use the [`PECL` extension](https://pecl.php.net/package/oauth). It's faster!

## Contributing

This is a work in progress, but the `OAuthClient` is usable as an alternative on systems that lack support. In some cases it may be preferred as it will not fatal in some edge cases where the PECL client will.

`OAuthProvider` is not yet complete. Please consider helping flesh out the `OAuthProvider` class or tests or both. This guide to [testing with docker](https://github.com/giberti/ext-oauth-shim/wiki/Testing-with-Docker) can be helpful when trying to contribute. Pull requests are welcome!

### Installing

This library requires PHP 7.3 or newer to use, including 8.0 or 8.1.

```
composer require giberti/ext-oauth-shim
```

## Usage

### Client

Most of the time, you'll be using this an OAuth client to request data. You'll start by creating an instance of the client and passing in your access token and secret.

```php
// Replace with your values
$consumer       = 'consumer';
$consumerSecret = 'secret';
$token          = 'token';
$tokenSecret    = 'secret';

// Create the client
$client = new OAuth($consumer, $consumerSecret);

// Set the access credentials
$client->setToken($token, $tokenSecret);
```

Now that you have a configured client, you can start making requests. To issue a simple GET request for a URI you can call `fetch()` with the url.

```php
// GET a protected resource
$response = $client->fetch('https://example.com/user/me');

```

Another common use case is to POST data, for example, posting a Tweet.

```php
// POST data to a protected resource
$postData = [
    'status' => 'Hello Twitter!'
];
$response = $client->fetch('https://api.twitter.com/1.1/statuses/update.json', $postData, 'POST');
```

This can also be used for more complicated payloads such JSON.

#### JSON Body

```php
$data = [
    'Name' => 'Jane Doe',
    'Age'  => '30',
];
$json = json_encode($data);

$headers = [
    'Content-type' => 'application/json',
];

$response = $client->fetch('https://example.com/user/janedoe', $json, 'POST', $headers);
```

#### Binary Body

An example of posting a GIF to an endpoint that accepts the binary image data.

```php
$image = file_get_contents('funny.gif');
$headers = [
    'Content-type' => 'image/gif',
];

$response = $client->fetch('https://example.com/image/', $image, 'POST', $headers);
```

### Obtaining an Access Token

Some providers do not automatically issue Access Tokens, if the API you are interacting with doesn't give you this token, you will need to create one.

```php
// Replace with your values
$consumer       = 'consumer';
$consumerSecret = 'secret';

// Create the client
$client = new OAuth($consumer, $consumerSecret);

// Set this to the callback page on your site
$callbackUrl = 'https://yoursite.com/oauth/finish';

// These two Urls are provided to you by the API provider
$requestTokenUrl  = 'https://example.com/oauth/request-token';
$authorizationUrl = 'https://example.com/oauth/authorize';

// Fetch a request token and store it in the session
$requestToken = $client->getRequestToken();

// Store the request token and secret for later
$_SESSION['requestToken'] = $requestToken;

// Redirect the browser to the authorization page
header('Location: ' . $authorizationUrl . '?' . urlencode($requestToken['oauth_token]));
```

The user's browser will be redirected to the service where they will grant permission to the application. Once they have completed this step, the browser will be redirected back to the callback url you provided in the first code sample.

```php
// Replace with your values
$consumer       = 'consumer';
$consumerSecret = 'secret';

$requestToken = $_SESSION['requestToken'];

// Create the client
$client = new OAuth($consumer, $consumerSecret);
$client->setToken($requestToken['oauth_token'], $requestToken['oauth_token_secret']);

$accessTokenUrl = 'https://example.com/oauth/access-token';

// Exchange the request token for a permanent access token
$accessToken = $client->getAccessToken($accessTokenUrl, null, $_REQUEST['oauth_verifier']);
$_SESSION['accessToken'] = $accessToken;
unset($_SESSION['requestToken']);
```

For all future requests, you'll use the access token to interact with the API.

```php
// Replace with your values
$consumer       = 'consumer';
$consumerSecret = 'secret';

$accessToken = $_SESSION['accessToken'];

// Create the client
$client = new OAuth($consumer, $consumerSecret);
$client->setToken($accessToken['oauth_token'], $accessToken['oauth_token_secret']);

// Fetch a resource
$response = $client->fetch('https://example.com/user/friends');
````