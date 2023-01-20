<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Psr\Factory;
use Conia\Chuck\Response;

class TestInvokableClass
{
    public function __invoke(Factory $factory)
    {
        return Response::fromFactory($factory)->html('Schuldiner');
    }
}
