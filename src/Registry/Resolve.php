<?php

declare(strict_types=1);

namespace Conia\Chuck\Registry;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS)]
class Resolve
{
    public function __construct(public readonly string $method)
    {
    }
}
