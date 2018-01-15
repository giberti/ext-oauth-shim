<?php
/**
 * Wrapper to only include classes if absolutely necessary
 *
 * Checks to see if the pecl extension is installed and only includes the class
 * files if the classes haven't already been defined already or by some other
 * code.
 */
if (!extension_loaded('OAuth')) {
    if (!class_exists('OAuth', false)) {
        include __DIR__ . '/classes/OAuth.php';
    }
    if (!class_exists('OAuthException', false)) {
        include __DIR__ . '/classes/OAuthException.php';
    }
    if (!class_exists('OAuthProvider', false)) {
        include __DIR__ . '/classes/OAuthProvider.php';
    }
}
