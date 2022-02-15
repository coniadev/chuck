<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\SessionInterface;


class Session
{
    public function __invoke(RequestInterface $request, callable|object $next): RequestInterface
    {
        $class = $request->config->registry(SessionInterface::class);
        $session = new $class($request->config);

        $request->addMethod('session', function () use ($session): SessionInterface {
            return $session;
        });

        return $next($request);
    }
}
