<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;

/**
 * @psalm-type MiddlewareClosure = Closure(\Conia\Chuck\RequestInterface, callable):\Conia\Chuck\Response\ResponseInterface
 * @psalm-type MiddlewareCallable = callable(\Conia\Chuck\RequestInterface, callable):\Conia\Chuck\Response\ResponseInterface
 */
interface MiddlewareInterface
{
    public function __invoke(
        RequestInterface $request,
        callable $next
    ): ResponseInterface;
}
