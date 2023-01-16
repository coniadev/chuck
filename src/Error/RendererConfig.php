<?php

declare(strict_types=1);

namespace Conia\Chuck\Error;

class RendererConfig
{
    public function __construct(
        public readonly string $renderer,
        public readonly array $args
    ) {
    }
}
