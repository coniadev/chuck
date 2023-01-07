<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class TestPsrMiddlewareObject implements MiddlewareInterface
{
    public function __construct(protected string $text)
    {
    }

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $next
    ): ResponseInterface {
        $response = $next->handle($request);
        $response->getBody()->write($this->text);

        return $response;
    }
}
