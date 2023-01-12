<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Conia\Chuck\MiddlewareInterface;
use Psr\Http\Server\MiddlewareInterface as PsrMiddlewareInterface;

/**
 * @psalm-type Middleware = callable|MiddlewareInterface|PsrMiddlewareInterface|non-empty-string
 * @psalm-type MiddlewareList = array<never,never>|list<Middleware>
 */
trait AddsMiddleware
{
    /** @psalm-var MiddlewareList */
    protected array $middleware = [];

    /** @psalm-param Middleware ...$middleware */
    public function middleware(
        MiddlewareInterface|PsrMiddlewareInterface|callable|string ...$middleware
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
