<?php

declare(strict_types=1);

namespace Chuck;

use \InvalidArgumentException;
use Chuck\Error\RegistryEntryNotFoundError;


class Registry implements RegistryInterface
{
    protected array $classes;
    protected array $instances;

    public function __construct()
    {
        $this->classes = [
            SessionInterface::class => Session::class,
            CsrfInterface::class => Csrf::class,
        ];
        $this->instances = [];
    }

    public function add(string $id, object|string $entry): void
    {
        if (is_object($entry)) {
            $this->instances[$id] = $entry;
            return;
        }

        if (!class_exists($entry)) {
            throw new InvalidArgumentException("Class does not exist: $entry");
        }

        if (interface_exists($id) && !is_subclass_of($entry, $id)) {
            throw new InvalidArgumentException(
                "$entry does not implement $id"
            );
        }

        if (class_exists($id) && !(is_subclass_of($entry, $id) || $entry === $id)) {
            throw new InvalidArgumentException(
                "$entry is no subclass of or the same class as $id"
            );
        }

        $this->classes[$id] = $entry;
    }

    public function has(string $id): bool
    {
        return array_key_exists($id, $this->classes)
            || array_key_exists($id, $this->instances);
    }

    public function get(string $id): mixed
    {
        if (array_key_exists($id, $this->classes)) {
            return $this->classes[$id];
        }

        if (array_key_exists($id, $this->instances)) {
            return $this->instances[$id];
        }

        throw new RegistryEntryNotFoundError("Undefined registry key \"$id\"");
    }

    public function new(string $id, mixed ...$args): object
    {
        return new ($this->get($id))(...$args);
    }

    public function instance(string $id): object
    {
        return $this->instances[$id] ??
            throw new InvalidArgumentException("Undefined registry key \"$id\"");
    }
}
