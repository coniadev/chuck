<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\MiddlewareWrapper;

/**
 * @psalm-import-type MiddlewareCallable from \Conia\Chuck\MiddlewareInterface
 */

trait AddsMiddleware
{
    /** @var array<never, never>|list<MiddlewareInterface> */
    protected array $middlewares = [];

    /** @param array<never, never>|list<MiddlewareInterface|MiddlewareCallable> $middlewares */
    public function middleware(MiddlewareInterface|callable ...$middlewares): static
    {
        $new = [];

        foreach ($middlewares as $middleware) {
            if ($middleware instanceof MiddlewareInterface) {
                $new[] = $middleware;
            } else {
                $new[] = new MiddlewareWrapper($middleware);
            }
        }

        $this->middlewares = array_merge($this->middlewares, $new);

        return $this;
    }

    /** @return array<never, never>|list<MiddlewareInterface> */
    public function middlewares(): array
    {
        return $this->middlewares;
    }

    /** @psalm-param list<MiddlewareInterface> $middlewares */
    public function replaceMiddleware(array $middlewares): static
    {
        $this->middlewares = $middlewares;

        return $this;
    }
}
