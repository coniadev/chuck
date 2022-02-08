<?php

declare(strict_types=1);

namespace Chuck;

interface MiddlewareInterface
{
    public function handle(
        RequestInterface $request,
        string|\Closure $next,
        mixed ...$args,
    ): RequestInterface;
}
