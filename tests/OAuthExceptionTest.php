<?php

use PHPUnit\Framework\TestCase;

class OAuthExceptionTest extends TestCase
{

    public function test_Throws(): void
    {
        $this->expectException(OAuthException::class);
        throw new OAuthException();
    }

    public function test_DefaultProperties(): void
    {
        $e = new OAuthException();
        $this->assertNull($e->lastResponse);
        $this->assertNull($e->debugInfo);
    }

}
