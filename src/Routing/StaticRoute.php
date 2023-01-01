<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

class StaticRoute
{
    public function __construct(
        readonly public string $prefix,
        readonly public string $dir
    ) {
    }
}
