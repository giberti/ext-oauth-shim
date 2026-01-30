<?php

include_once __DIR__.'/../vendor/autoload.php';

// Older versions of PHPUnit supported elevating warnings, notices, and errors
// to exceptions which allowed for inspection. This is added here to preserve
// the behavior and keep as much parity with the pecl extension as possible.
set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    throw new \ErrorException($message, 0, $severity, $file, $line);
});