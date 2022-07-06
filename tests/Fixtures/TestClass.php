<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;


class TestClass implements TestInterface
{
    public function test(): string
    {
        return '';
    }

    public function __toString(): string
    {
        return 'Stringable';
    }
}
