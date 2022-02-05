<?php

declare(strict_types=1);

namespace Chuck\Model;

use Chuck\Util\Arrays;


class Args
{
    protected ArgType $type;
    protected int $count;

    public function __construct(array $args)
    {
        $this->args = $this->prepare($args);
    }

    protected function prepare(array $args)
    {

        $this->count = count($args);

        if ($this->count === 1 && is_array($args[0])) {
            if (Arrays::isAssoc($args[0])) {
                $this->type = ArgType::Assoc;
            } else {
                $this->type = ArgType::Args;
            }

            return $args[0];
        }

        $this->type = ArgType::Args;

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
