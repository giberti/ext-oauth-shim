<?php

// Shared Access, Consumer, and Request Tokens and Secrets

return [
    'access-tokens'          => [
        'token'         => 'secret',
        'token-expired' => 'secret',
        'token-invalid' => 'invalid',
    ],
    'consumer-tokens'        => [
        'consumer'         => 'secret',
        'consumer-invalid' => 'invalid',
        'consumer-refused' => 'secret',
    ],
    'request-tokens'         => [
        'request-token'         => 'request-secret',
        'request-token-expired' => 'request-secret',
        'request-token-invalid' => 'invalid',
    ],
    'request-token-verifier' => '123456',
];
