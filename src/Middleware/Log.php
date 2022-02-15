<?php

declare(strict_types=1);

namespace Chuck\Middleware;

use Psr\Log\LoggerInterface;

use Chuck\RequestInterface;


class Log
{
    public function __construct(protected LoggerInterface $logger)
    {
    }

    public function __invoke(RequestInterface $request, callable|object $next): RequestInterface
    {
        $request->addMethod('log', function () use ($this): LoggerInterface {
            return $this->logger;
        });

        return $next($request);
    }
}
