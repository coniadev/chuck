<?php

declare(strict_types=1);

namespace Chuck\Tests\Fixtures;

use \Attribute;
use Chuck\Middleware\MiddlewareInterface;
use Chuck\RequestInterface;
use Chuck\Response\ResponseInterface;


#[Attribute]
class TestMiddleware1 implements MiddlewareInterface
{
    public function __invoke(RequestInterface $request, callable $next): RequestInterface|ResponseInterface
    {
        $request->addMethod('test', fn () => 'attribute-string');

        return $next($request);
    }
}
