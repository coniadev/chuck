<?php

declare(strict_types=1);

namespace Conia\Chuck\Middleware;

use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;

interface MiddlewareInterface
{
    public function __invoke(
        RequestInterface $request,
        callable $next
    ): RequestInterface|ResponseInterface;
}
