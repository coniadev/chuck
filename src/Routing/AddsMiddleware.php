<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\MiddlewareWrapper;

trait AddsMiddleware
{
    /** @var list<MiddlewareInterface> */
    protected array $middlewares = [];

    public function middleware(callable ...$middlewares): static
    {
        foreach ($middlewares as $middleware) {
            if ($middleware instanceof MiddlewareInterface) {
                $this->middlewares[] = $middleware;
            } else {
                $this->middlewares[] = new MiddlewareWrapper($middleware);
            }
        }

        return $this;
    }

    /** @return list<MiddlewareInterface> */
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
