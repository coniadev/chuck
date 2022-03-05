<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\ResponseInterface;
use Chuck\Logger;

class Logging
{
    public function __invoke(RequestInterface $request, callable $next): RequestInterface|ResponseInterface
    {
        $request->addMethod('logger', function () use ($request): Logger {
            $logConfig = $request->getConfig()->log();


            return new Logger(
                $logConfig->level,
                $logConfig->file,
            );
        });

        return $next($request);
    }
}
