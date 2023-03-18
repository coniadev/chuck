<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Closure;
use Conia\Chuck\Middleware;
use Psr\Http\Server\MiddlewareInterface as PsrMiddleware;

trait AddsMiddleware
{
    /** @var list<list{non-falsy-string, ...}|Closure|Middleware|PsrMiddleware> */
    protected array $middleware = [];

    /** @psalm-param non-falsy-string|list{non-falsy-string, ...}|Closure|Middleware|PsrMiddleware ...$middleware */
    public function middleware(string|array|Closure|Middleware|PsrMiddleware ...$middleware): static
    {
        $this->middleware = array_merge($this->middleware, array_map(function ($mw) {
            if (is_string($mw)) {
                return [$mw];
            }

            return $mw;
        }, array_values($middleware)));

        return $this;
    }

    /** @psalm-return list<list{non-falsy-string, ...}|Closure|Middleware|PsrMiddleware> */
    public function getMiddleware(): array
    {
        return $this->middleware;
    }

    /** @psalm-param list<list{non-falsy-string, ...}|Closure|Middleware|PsrMiddleware> $middleware */
    public function replaceMiddleware(array $middleware): static
    {
        $this->middleware = $middleware;

        return $this;
    }
}
