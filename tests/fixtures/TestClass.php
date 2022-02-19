<?php

declare(strict_types=1);

namespace Chuck\Tests\Fix;

use Chuck\Tests\Fix\TestInterface;


class TestClass implements TestInterface
{
    function test(): string
    {
        return '';
    }
}
