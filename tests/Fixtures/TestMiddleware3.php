<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Middleware;
use Conia\Chuck\Request;
use Conia\Chuck\Response;

class TestMiddleware3 implements Middleware
{
    public function __invoke(Request $request, callable $next): Response
    {
        return $next($request);
    }
}
