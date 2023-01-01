<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;

/**
 * @psalm-import-type MiddlewareCallable from \Conia\Chuck\MiddlewareInterface
 * @psalm-import-type MiddlewareClosure from \Conia\Chuck\MiddlewareInterface
 */

class MiddlewareWrapper implements MiddlewareInterface
{
    /** @var MiddlewareClosure */
    protected Closure $callable;

    /**
     * @param MiddlewareCallable $callable
     */
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
