<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Request;
use Conia\Chuck\Response\ResponseInterface;

/**
 * @psalm-type MiddlewareClosure = Closure(
 *     \Conia\Chuck\Request,
 *     callable
 * ):\Conia\Chuck\Response\ResponseInterface
 *
 * @psalm-type MiddlewareCallable = callable(
 *     \Conia\Chuck\Request,
 *     callable
 * ):\Conia\Chuck\Response\ResponseInterface
 */
interface MiddlewareInterface
{
    public function __invoke(
        Request $request,
        callable $next
    ): ResponseInterface;
}
