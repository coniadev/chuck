<?php

declare(strict_types=1);

namespace Chuck\Database;

use Chuck\Util\Arrays;


class Args
{
    protected ArgType $type;
    protected int $count;
    protected readonly array $args;

    public function __construct(array $args)
    {
        $this->args = $this->prepare($args);
    }

    protected function prepare(array $args): array
    {

        $this->count = count($args);

        if ($this->count === 1 && is_array($args[0])) {
            if (Arrays::isAssoc($args[0])) {
                $this->type = ArgType::Named;
            } else {
                $this->type = ArgType::Positional;
            }

            return $args[0];
        }

        $this->type = ArgType::Positional;

        return $args;
    }

    public function get(): array
    {
        return $this->args;
    }

    public function count(): int
    {
        return $this->count;
    }

    public function type(): ArgType
    {
        return $this->type;
    }
}
