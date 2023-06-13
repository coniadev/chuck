<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Psr\Http\Message\ResponseInterface as PsrResponse;
use Psr\Http\Message\ServerRequestInterface as PsrServerRequest;
use Psr\Http\Server\MiddlewareInterface as PsrMiddleware;
use Psr\Http\Server\RequestHandlerInterface as PsrRequestHandler;

class TestPsrMiddlewareObject implements PsrMiddleware
{
    public function __construct(protected string $text)
    {
    }

    public function process(
        PsrServerRequest $request,
        PsrRequestHandler $next
    ): PsrResponse {
        $response = $next->handle($request);
        $body = $response->getBody();
        $content = (string)$body . $this->text;
        $body->seek(0);
        $body->write($content);

        return $response;
    }
}
