<?php

declare(strict_types=1);

namespace Conia\Chuck\Error;

/** @psalm-api */
class Error
{
    public function __construct(
        public readonly string $error,
        public readonly string $description,
        public readonly string $traceback,
        public readonly int $code,
    ) {
    }
}
