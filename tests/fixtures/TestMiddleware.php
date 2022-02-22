<?php

declare(strict_types=1);

namespace Chuck\Tests\Fix;

use Chuck\Request;
use Chuck\Response;


class TestMiddleware
{
    public function __invoke(Request $request, callable $next): Request|Response
    {
        return $next($request);
    }
}
