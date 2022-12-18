<?php

declare(strict_types=1);

namespace Conia\Chuck;

use OutOfBoundsException;

class Registry
{
    protected array $entries = [];

    public function add(string $id, object|string|null $entry = null): void
    {
        if (func_num_args() === 1) {
            $this->entries[$id] = $id;
            return;
        }

        $this->entries[$id] = $entry;
    }

    public function has(string $id): bool
    {
        return isset($this->entries[$id]) || array_key_exists($id, $this->entries);
    }

    public function get(string $id): mixed
    {
        if (isset($this->entries[$id]) || array_key_exists($id, $this->entries)) {
            return $this->entries[$id];
        }

        throw new OutOfBoundsException("Undefined registry key \"$id\"");
    }

    public function new(string $id, mixed ...$args): object
    {
        return new ($this->get($id))(...$args);
    }
}
