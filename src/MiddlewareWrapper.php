<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\Request;
use Conia\Chuck\Response;

/**
 * @psalm-import-type MiddlewareCallable from \Conia\Chuck\MiddlewareInterface
 * @psalm-import-type MiddlewareClosure from \Conia\Chuck\MiddlewareInterface
 */
class MiddlewareWrapper implements MiddlewareInterface
{
    /** @psalm-var MiddlewareClosure */
    protected Closure $callable;

    /**
     * @psalm-param MiddlewareCallable $callable
     */
    public function __construct(callable $callable)
    {
        $this->callable = Closure::fromCallable($callable);
    }

    public function __invoke(
        Request $request,
        callable $next
    ): Response {
        return ($this->callable)($request, $next);
    }
}
