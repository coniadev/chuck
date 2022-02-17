<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\SessionInterface;


class Session
{
    public function __invoke(RequestInterface $request, callable $next): RequestInterface
    {
        $class = $request->getConfig()->registry(SessionInterface::class);
        /** @var SessionInterface */
        $session = new $class($request);

        $request->addMethod('session', function () use ($session): SessionInterface {
            return $session;
        });

        return $next($request);
    }
}
