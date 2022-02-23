<?php

declare(strict_types=1);

namespace Chuck\Routing;


interface GroupInterface
{
    public function create(RouterInterface $router): void;
}
