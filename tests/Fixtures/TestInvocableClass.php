<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Registry;
use Conia\Chuck\ResponseFactory;

class TestInvocableClass
{
    public function __invoke(Registry $registry)
    {
        return (new ResponseFactory($registry))->html('Schuldiner');
    }
}
