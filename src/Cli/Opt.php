<?php

declare(strict_types=1);

namespace Conia\Chuck\Cli;


class Opt
{
    protected array $values;

    public function __construct()
    {
        $this->values = [];
    }

    public function set(string $value): void
    {
        $this->values[] = $value;
    }

    public function get(): string
    {
        return $this->values[0];
    }

    public function all(): array
    {
        return $this->values;
    }

    public function isset(): bool
    {
        return count($this->values) > 0;
    }
}
