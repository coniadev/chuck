<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Psr\Factory;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;

class TestMiddlewareEarlyResponse
{
    public function __construct(protected string $text, protected Factory $factory)
    {
    }

    public function __invoke(Request $request, callable $_): Response
    {
        return (new ResponseFactory($this->factory))->html($this->text);
    }
}
