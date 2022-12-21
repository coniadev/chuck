<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Request;
use Conia\Chuck\Config;

class TestClassIntersectionTypeConstructor
{
    public function __construct(Config&Request $param)
    {
    }
}
