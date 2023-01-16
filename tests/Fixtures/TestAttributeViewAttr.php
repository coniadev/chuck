<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Attribute;
use Conia\Chuck\Config;
use Conia\Chuck\Di\Call;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;

#[Attribute, Call('initialize'), Call('after', after: 'Called after')]
class TestAttributeViewAttr
{
    public ?Registry $registry = null;
    public ?Config $config = null;
    public ?Request $request = null;
    public string $after = '';

    public function __construct(public readonly string $name = '')
    {
    }

    public function initialize(Registry $registry, Config $config): void
    {
        $this->registry = $registry;
        $this->config = $config;
    }

    public function after(Request $request, string $after): void
    {
        $this->request = $request;
        $this->after = $after;
    }
}
