<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;

class MiddlewareWrapper implements MiddlewareInterface
{
    protected Closure $callable;

    public function __construct(callable $callable)
    {
        $this->callable = Closure::fromCallable($callable);
    }

    public function __invoke(
        RequestInterface $request,
        callable $next
    ): ResponseInterface {
        return ($this->callable)($request, $next);
    }
}
