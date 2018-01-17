<?php

/**
 * Class OAuthException
 *
 * This exception is thrown when exceptional errors occur while using the OAuth extension and contains useful debugging
 * information.
 *
 * @see http://php.net/manual/en/class.oauthexception.php
 */
class OAuthException extends \Exception
{

    /**
     * The response of the exception which occurred, if any
     *
     * @var mixed $lastResponse
     */
    public $lastResponse;

    /**
     * @var $debugInfo
     */
    public $debugInfo;

}