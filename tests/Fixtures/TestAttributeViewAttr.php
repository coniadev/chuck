<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Attribute;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\ViewAttributeInterface;

#[Attribute]
class TestAttributeViewAttr implements ViewAttributeInterface
{
    public ?Registry $registry = null;

    public function __construct(public readonly string $name = '')
    {
    }

    public function injectRegistry(Registry $registry): void
    {
        $this->registry = $registry;
    }
}
