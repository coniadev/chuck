<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\Response\ResponseInterface;


interface MiddlewareInterface
{
    public function __invoke(
        RequestInterface $request,
        callable $next
    ): RequestInterface|ResponseInterface;
}
