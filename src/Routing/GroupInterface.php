<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

interface GroupInterface
{
    public function create(Router $router): void;
}
