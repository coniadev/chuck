<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Attribute;
use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;

#[Attribute]
class TestMiddleware1 implements MiddlewareInterface
{
    public function __invoke(RequestInterface $request, callable $next): ResponseInterface
    {
        return $next($request);
    }
}
