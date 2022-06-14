<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\Response\ResponseInterface;
use Chuck\Csrf as CsrfBase;


class Csrf
{
    public function __invoke(RequestInterface $request, callable $next): RequestInterface|ResponseInterface
    {
        $request->addMethod('csrf', function (): CsrfBase {
            return new CsrfBase();;
        });

        return $next($request);
    }
}
