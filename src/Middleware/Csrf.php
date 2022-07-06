<?php

declare(strict_types=1);

namespace Conia\Chuck\Middleware;

use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;
use Conia\Chuck\Csrf as CsrfBase;


class Csrf implements MiddlewareInterface
{
    public function __invoke(
        RequestInterface $request,
        callable $next
    ): RequestInterface|ResponseInterface {
        $request->addMethod('csrf', function (): CsrfBase {
            return new CsrfBase();;
        });

        return $next($request);
    }
}
