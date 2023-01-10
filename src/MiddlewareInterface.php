<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Request;
use Conia\Chuck\Response;

/**
 * @psalm-type MiddlewareClosure = Closure(
 *     \Conia\Chuck\Request,
 *     callable
 * ):\Conia\Chuck\Response
 * @psalm-type MiddlewareCallable = callable(
 *     \Conia\Chuck\Request,
 *     callable
 * ):\Conia\Chuck\Response
 */
interface MiddlewareInterface
{
    public function __invoke(
        Request $request,
        callable $next
    ): Response;
}
