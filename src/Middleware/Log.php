<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\Util\Log as LogUtil;


class Log
{
    public function __invoke(RequestInterface $request, callable $next): RequestInterface
    {
        $request->addMethod('log', function (int $level, string $message) use ($request): void {
            LogUtil::log($request, $level, $message);
        });

        return $next($request);
    }
}
