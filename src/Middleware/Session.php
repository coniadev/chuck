<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\ResponseInterface;
use Chuck\SessionInterface;


class Session
{
    public function __invoke(RequestInterface $request, callable $next): RequestInterface|ResponseInterface
    {
        /** @var SessionInterface */
        $session = $request->getConfig()->registry->new(SessionInterface::class, $request);
        $session->start();

        $request->addMethod('session', function () use ($session): SessionInterface {
            return $session;
        });

        return $next($request);
    }
}
