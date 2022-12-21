<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Config;

class TestClassRegistryArgs
{
    public function __construct(
        public readonly TestClass $tc,
        public readonly string $test,
        public readonly ?Config $config = null,
    ) {
    }
}
