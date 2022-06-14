<?php

declare(strict_types=1);

namespace Chuck\Tests\Fixtures;

use Chuck\Request;
use Chuck\Response\Response;


class TestMiddleware1
{
    public function __invoke(Request $request, callable $next): Request|Response
    {
        return $next($request);
    }
}
