<?php

declare(strict_types=1);

namespace Chuck;

use \InvalidArgumentException;
use Chuck\Renderer\RendererInterface;

class Registry implements RegistryInterface
{
    protected array $classes;
    protected array $objects;
    protected array $renderers;

    public function __construct()
    {
        $this->classes = [
            RequestInterface::class => Request::class,
            ResponseInterface::class => Response::class,
            TemplateInterface::class => Template::class,
            SessionInterface::class => Session::class,
        ];
        $this->objects = [];
        $this->renderers = [
            'text' => Renderer\TextRenderer::class,
            'json' => Renderer\JsonRenderer::class,
            'template' => Renderer\TemplateRenderer::class,
        ];
    }

    public function add(string $key, string|object $entry): void
    {
        if (is_object($entry)) {
            $this->objects[$key] = $entry;
            $this->classes[$key] = $entry::class;
            return;
        }

        if (is_subclass_of($entry, RendererInterface::class)) {
            $this->renderers[$key] = $entry;
            return;
        }

        if (!class_exists($entry)) {
            throw new InvalidArgumentException("Class does not exist: $entry");
        }

        /** @var class-string $key */
        if (!(is_subclass_of($entry, $key) || $entry === $key)) {
            throw new InvalidArgumentException(
                "$entry is no subclass of or does not implement $key"
            );
        }

        $this->classes[$key] = $entry;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->classes)
            || array_key_exists($key, $this->renderers)
            || array_key_exists($key, $this->objects);
    }

    public function get(string $key): string
    {
        if (array_key_exists($key, $this->classes)) {
            return $this->classes[$key];
        }

        return $this->renderers[$key] ??
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
