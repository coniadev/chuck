<?php

declare(strict_types=1);

namespace Conia\Chuck\Middleware;

use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;
use Conia\Chuck\Session as SessionBase;


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
