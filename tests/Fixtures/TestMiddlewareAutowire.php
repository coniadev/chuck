<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Config;
use Conia\Chuck\Middleware;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;

class TestMiddlewareAutowire implements Middleware
{
    public function __construct(protected Registry $registry, protected Config $config)
    {
    }

    public function __invoke(Request $request, callable $next): Response
    {
        $response = $next($request);
        $response->write($this->config->app() . ' ' . $this->registry::class);

        return $response;
    }
}
