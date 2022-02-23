<?php

declare(strict_types=1);

namespace Chuck;

use \InvalidArgumentException;


class Registry
{
    protected array $classes;
    protected array $objects;

    public function __construct()
    {
        $this->classes = [
            RequestInterface::class => Request::class,
            ResponseInterface::class => Response::class,
            TemplateInterface::class => Template::class,
            SessionInterface::class => Session::class,
        ];
    }

    public function add(string $key, string|object $entry): void
    {
        if (!interface_exists($key)) {
            throw new InvalidArgumentException("Interface does not exist: $key");
        }

        if (is_object($entry)) {
            $this->objects[$key] = $entry;
            return;
        }

        if (!class_exists($entry)) {
            throw new InvalidArgumentException("Class does not exist: $entry");
        }

        if (!(is_subclass_of($entry, $key) || $entry === $key)) {
            throw new InvalidArgumentException(
                "$entry is no subclass of or does not implement $key"
            );
        }

        $this->classes[$key] = $entry;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->registry);
    }

    public function get(string $key): string
    {
        return $this->classes[$key] ??
            throw new InvalidArgumentException("Undefined registry key \"$key\"");
    }

    public function new(string $key, mixed ...$args): object
    {
        return new ($this->get($key))(...$args);
    }

    public function obj(string $key): object
    {
        return $this->objects[$key] ??
            throw new InvalidArgumentException("Undefined registry key \"$key\"");
    }
}
