<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Config;
use Conia\Chuck\Di\Call;
use Conia\Chuck\Di\Inject;
use Conia\Chuck\Factory;
use Conia\Chuck\Middleware;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;

#[Call('init')]
class TestMiddlewareBench implements Middleware
{
    public ?Factory $factory = null;
    public string $calledArg1 = '';
    public int $calledArg2 = 0;

    public function __construct(protected Registry $registry, protected Config $config)
    {
    }

    public function __invoke(Request $request, callable $next): Response
    {
        return $next($request);
    }

    #[Inject(calledArg2: 73, calledArg1: 'calledArg1')]
    public function init(string $calledArg1, int $calledArg2, Factory $factory): void
    {
        $this->calledArg1 = $calledArg1;
        $this->calledArg2 = $calledArg2;
        $this->factory = $factory;
    }
}
