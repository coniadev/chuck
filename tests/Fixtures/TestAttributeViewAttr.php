<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Attribute;
use Conia\Chuck\Config;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Registry\Resolve;

#[Attribute, Resolve('initialize')]
class TestAttributeViewAttr
{
    public ?Registry $registry = null;
    public ?Config $config = null;

    public function __construct(public readonly string $name = '')
    {
    }

    public function initialize(Registry $registry, Config $config): void
    {
        $this->registry = $registry;
        $this->config = $config;
    }
}
