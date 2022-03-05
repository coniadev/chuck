<?php

declare(strict_types=1);

namespace Chuck\Template;

class Context
{
    public function __construct(protected array $context)
    {
    }

    public function __get(string $name): mixed
    {
        $value = $this->context[$name];

        if (!is_string($value) && !method_exists($value, '__toString')) {
            return $value;
        }

        return new Value($value);
    }
}
