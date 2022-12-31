<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

readonly class StaticRoute {
    public function __construct(public string $prefix, public string $dir)
    {
    }
}
