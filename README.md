# OAuth Extension Shim

Provides `OAuth`, `OAuthException`, and `OAuthProvider` and meets the `ext-oauth` requirement for composer packages that require it.

**WARNING:** If at all possible, you should use the `pecl` extension. It's faster and more complete.

## Quality

[![Build Status](https://api.travis-ci.org/giberti/ext-oauth-shim.svg?branch=master)](https://travis-ci.org/giberti/ext-oauth-shim)

## Contributing

This is a work in progress. Please consider helping flesh out the `OAuth` and `OAuthProvider` classes.

Pull requests are welcome!

### Installing

This library requires PHP 7.0 or newer. It _may_ run under PHP 5.6 but it is not supported.

```
composer require giberti/ext-oauth-shim
```

