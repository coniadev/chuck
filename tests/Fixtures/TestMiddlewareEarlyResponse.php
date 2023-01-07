<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;

class TestMiddlewareEarlyResponse
{
    public function __construct(protected string $text, protected Registry $registry)
    {
    }

    public function __invoke(Request $request, callable $_): Response
    {
        $response = (new ResponseFactory($this->registry))->html($this->text);

        return $response;
    }
}
