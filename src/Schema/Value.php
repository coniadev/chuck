<?php

declare(strict_types=1);

namespace Conia\Chuck\Schema;


class Value
{
    public function __construct(
        public mixed $value,
        public mixed $pristine,
        public null|array|string $error = null,
    ) {
    }
}
