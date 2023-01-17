<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Psr\Factory;
use Conia\Chuck\ResponseFactory;

class TestInvokableClass
{
    public function __invoke(Factory $factory)
    {
        return (new ResponseFactory($factory))->html('Schuldiner');
    }
}
