<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Di\Call;
use Conia\Chuck\Di\Inject;
use Conia\Chuck\Registry;

#[Call('callThis')]
class TestClassInject
{
    public ?Registry $registry = null;
    public ?TestConfig $config = null;
    public ?TestClass $tc = null;
    public string $arg1 = '';
    public int $arg2 = 0;
    public string $calledArg1 = '';
    public int $calledArg2 = 0;

    #[Inject(arg2: 13, tc: TestClassExtended::class), Inject(config: 'injected', arg1: 'arg1')]
    public function __construct(
        string $arg1,
        Registry $registry,
        TestConfig $config,
        int $arg2,
        TestClass $tc,
    ) {
        $this->registry = $registry;
        $this->config = $config;
        $this->arg1 = $arg1;
        $this->arg2 = $arg2;
        $this->tc = $tc;
    }

    #[Inject(calledArg2: 73, calledArg1: 'calledArg1')]
    public function callThis(string $calledArg1, int $calledArg2): void
    {
        $this->calledArg1 = $calledArg1;
        $this->calledArg2 = $calledArg2;
    }
}
