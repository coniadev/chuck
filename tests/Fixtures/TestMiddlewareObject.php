<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Request;
use Conia\Chuck\Response;

class TestMiddlewareObject
{
    public function __construct(protected string $text)
    {
    }

    public function __invoke(Request $request, callable $next): Response
    {
        $response = $next($request);
        $response->body((string)$response->getBody()  . $this->text);

        return $response;
    }
}
