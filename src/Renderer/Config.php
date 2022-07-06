<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;


class Config
{
    public function __construct(
        public readonly string $type,
        public readonly array $args,
    ) {
    }
}
