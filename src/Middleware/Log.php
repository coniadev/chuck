<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;

class Log
{
    public function __invoke(RequestInterface $request, callable $next): RequestInterface
    {
        $request->addMethod('logger', function () use ($request): \Chuck\Log {
            return new \Chuck\Log($request);
        });

        return $next($request);
    }
}
