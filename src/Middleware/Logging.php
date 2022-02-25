<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\Logger;

class Logging
{
    public function __invoke(RequestInterface $request, callable $next): RequestInterface
    {
        $request->addMethod('logger', function () use ($request): Logger {
            $config = $request->getConfig();

            return new Logger($config->get('loglevel'), $config->pathOrNull('logfile'));
        });

        return $next($request);
    }
}
