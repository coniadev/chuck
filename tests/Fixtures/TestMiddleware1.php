<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Attribute;
use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\Request;
use Conia\Chuck\Response\ResponseInterface;

#[Attribute]
class TestMiddleware1 implements MiddlewareInterface
{
    public function __invoke(Request $request, callable $next): ResponseInterface
    {
        return $next($request);
    }
}
