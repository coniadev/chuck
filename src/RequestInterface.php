<?php

declare(strict_types=1);

namespace Conia\Chuck;

interface RequestInterface
{
    public function config(): ConfigInterface;
    public function response(): ResponseFactory;
    public function method(): string;
}
