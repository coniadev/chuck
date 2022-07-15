<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Routing\RouterInterface;

interface RequestInterface
{
    public function config(): ConfigInterface;
    public function router(): RouterInterface;
    public function response(): ResponseFactory;
    public function method(): string;
    public function addMethod(string $name, callable $callable): void;
}
