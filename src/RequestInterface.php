<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Routing\RouterInterface;


interface RequestInterface
{
    public function config(): ConfigInterface;
    public function router(): RouterInterface;
    public function response(): ResponseFactory;
    public function method(): string;
    public function addMethod(string $name, callable $callable): void;
}
