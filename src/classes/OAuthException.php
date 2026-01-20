<?php

/**
 * Class OAuthException
 *
 * This exception is thrown when exceptional errors occur while using the OAuth extension and contains useful debugging
 * information.
 *
 * @see https://php.net/manual/en/class.oauthexception.php
 */
class OAuthException extends \Exception
{

    /**
     * The response of the exception which occurred, if any
     *
     * @var mixed $lastResponse
     */
    public $lastResponse;

    public $debugInfo;

    public $additionalInfo;
}
