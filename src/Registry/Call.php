<?php

declare(strict_types=1);

namespace Conia\Chuck\Registry;

use Attribute;
use Conia\Chuck\Exception\RuntimeException;

#[Attribute(Attribute::IS_REPEATABLE | Attribute::TARGET_CLASS)]
class Call
{
    protected ?array $args = null;

    public function __construct(public readonly string $method, mixed ...$args)
    {
        if (count($args) > 1) {
            if (is_int(array_key_first($args))) {
                throw new RuntimeException('Arguments of Call must be named arguments');
            }

            $this->args = $args;
        }
    }

    public function args(): ?array
    {
        return $this->args;
    }
}
