<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

class TestClass implements TestInterface
{
    public function __toString(): string
    {
        return 'Stringable';
    }

    public function test(): string
    {
        return '';
    }
}
