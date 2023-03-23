<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Di\Call;
use Conia\Chuck\Factory;
use Conia\Chuck\Registry;

#[Call('method1'), Call('method2', arg2: 'arg2', arg1: 'arg1')]
class TestClassCall
{
    public ?Registry $registry = null;
    public ?TestConfig $config = null;
    public ?Factory $factory = null;
    public string $arg1 = '';
    public string $arg2 = '';

    public function method1(Registry $registry, TestConfig $config): void
    {
        $this->registry = $registry;
        $this->config = $config;
    }

    public function method2(string $arg1, Factory $factory, string $arg2): void
    {
        $this->factory = $factory;
        $this->arg1 = $arg1;
        $this->arg2 = $arg2;
    }
}
