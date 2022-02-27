<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Chuck\RequestInterface;
use Chuck\ResponseInterface;
use Chuck\CsrfInterface;


class Csrf
{
    public function __invoke(RequestInterface $request, callable $next): RequestInterface|ResponseInterface
    {
        $request->addMethod('csrf', function () use ($request): CsrfInterface {
            /** @var CsrfInterface */
            return $request->getRegistry()->new(CsrfInterface::class);;
        });

        return $next($request);
    }
}
