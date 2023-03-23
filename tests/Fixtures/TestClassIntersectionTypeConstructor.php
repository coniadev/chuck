<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Request;

class TestClassIntersectionTypeConstructor
{
    public function __construct(TestConfig&Request $param)
    {
    }
}
