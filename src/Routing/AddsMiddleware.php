<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\MiddlewareWrapper;
use Psr\Http\Server\MiddlewareInterface as PsrMiddlewareInterface;

/**
 * @psalm-import-type MiddlewareCallable from \Conia\Chuck\MiddlewareInterface
 * @psalm-type ValidMiddleware = MiddlewareInterface|PsrMiddlewareInterface|MiddlewareCallable
 * @psalm-type MiddlewareList = array<never, never>|list<MiddlewareInterface|PsrMiddlewareInterface>
 */
trait AddsMiddleware
{
    /** @var MiddlewareList */
    protected array $middleware = [];

    /** @param ValidMiddleware ...$middleware */
    public function middleware(
        MiddlewareInterface|PsrMiddlewareInterface|callable ...$middleware
    ): static {
        $new = [];

        foreach ($middleware as $mw) {
            if (
                ($mw instanceof MiddlewareInterface) ||
                ($mw instanceof PsrMiddlewareInterface)
            ) {
                $new[] = $mw;
            } else {
                $new[] = new MiddlewareWrapper($mw);
            }
        }

        $this->middleware = array_merge($this->middleware, $new);

        return $this;
    }

    /** @return MiddlewareList */
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
