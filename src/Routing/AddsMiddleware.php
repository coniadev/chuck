<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Conia\Chuck\Middleware;
use Psr\Http\Server\MiddlewareInterface as PsrMiddleware;

/**
 * @psalm-type Middleware = callable|Middleware|PsrMiddleware|non-empty-string
 * @psalm-type MiddlewareList = array<never,never>|list<Middleware>
 */
trait AddsMiddleware
{
    /** @psalm-var MiddlewareList */
    protected array $middleware = [];

    /** @psalm-param Middleware ...$middleware */
    public function middleware(
        Middleware|PsrMiddleware|callable|string ...$middleware
    ): static {
        $this->middleware = array_merge($this->middleware, array_values($middleware));

        return $this;
    }

    /** @psalm-return MiddlewareList */
    public function getMiddleware(): array
    {
        return $this->middleware;
    }

    /** @psalm-param MiddlewareList $middleware */
    public function replaceMiddleware(array $middleware): static
    {
        $this->middleware = $middleware;

        return $this;
    }
}
