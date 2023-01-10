<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Config;
use Conia\Chuck\Request;

class TestClassRegistryNamedParam
{
    public function __construct(
        public readonly Config $config,
        public readonly Config $namedConfig
    ) {
    }
}
