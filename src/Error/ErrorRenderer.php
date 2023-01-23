<?php

declare(strict_types=1);

namespace Conia\Chuck\Error;

/** @psalm-api */
class ErrorRenderer
{
    public function __construct(
        public readonly string $renderer,
        public readonly array $args
    ) {
    }
}
