<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\Request;
use Conia\Chuck\Response;

class MiddlewareWrapper implements MiddlewareInterface
{
    protected Closure $callable;

    /** @psalm-param callable(Request, callable):Response $callable */
    public function __construct(callable $callable)
    {
        $this->callable = Closure::fromCallable($callable);
    }

    public function __invoke(
        Request $request,
        callable $next
    ): Response {
        /** @psalm-var Closure(Request, callable):Response $this->callable */
        return ($this->callable)($request, $next);
    }
}
