<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\Util;


class Log
{
    public function __invoke(RequestInterface $request, callable $next): RequestInterface
    {
        $request->addMethod('logger', function () use ($request): Util\Log {
            return new Util\Log($request);
        });

        return $next($request);
    }
}
