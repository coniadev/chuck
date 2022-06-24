<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\Response\ResponseInterface;
use Chuck\Session as SessionBase;


class Session implements MiddlewareInterface
{
    public function __invoke(
        RequestInterface $request,
        callable $next
    ): RequestInterface|ResponseInterface {
        $session = new SessionBase($request->config()->app());
        $session->start();

        $request->addMethod('session', function () use ($session): SessionBase {
            return $session;
        });

        return $next($request);
    }
}
