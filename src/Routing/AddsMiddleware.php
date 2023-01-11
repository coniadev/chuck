<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Conia\Chuck\MiddlewareInterface;
use Psr\Http\Server\MiddlewareInterface as PsrMiddlewareInterface;

trait AddsMiddleware
{
    protected array $middleware = [];

    public function middleware(
        MiddlewareInterface|PsrMiddlewareInterface|callable|string ...$middleware
    ): static {
        $this->middleware = array_merge($this->middleware, array_values($middleware));

        return $this;
    }

    public function getMiddleware(): array
    {
        return $this->middleware;
    }

    public function replaceMiddleware(array $middleware): static
    {
        $this->middleware = $middleware;

        return $this;
    }
}
