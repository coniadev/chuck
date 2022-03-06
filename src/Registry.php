<?php

declare(strict_types=1);

namespace Chuck;

use \InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Chuck\Error\RegistryEntryNotFoundError;
use Chuck\Renderer\RendererInterface;
use Chuck\Routing\{Router, RouterInterface};
use Chuck\Template\{Engine, TemplateEngine};


class Registry implements RegistryInterface
{
    protected array $classes;
    protected array $instances;
    /** @var array<string, class-string<RendererInterface>> */
    protected array $renderers;

    public function __construct()
    {
        $this->classes = [
            RequestInterface::class => Request::class,
            ResponseInterface::class => Response::class,
            RouterInterface::class => Router::class,
            SessionInterface::class => Session::class,
            CsrfInterface::class => Csrf::class,
            TemplateEngine::class => Engine::class,
        ];
        $this->instances = [];
        $this->renderers = [
            'text' => Renderer\TextRenderer::class,
            'json' => Renderer\JsonRenderer::class,
            'template' => Renderer\TemplateRenderer::class,
        ];
    }

    public function add(string $id, object|string $entry): void
    {
        if (is_object($entry)) {
            $this->instances[$id] = $entry;
            return;
        }

        if (is_subclass_of($entry, RendererInterface::class)) {
            $this->renderers[$id] = $entry;
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
            || array_key_exists($id, $this->renderers)
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

        if (array_key_exists($id, $this->renderers)) {
            return $this->renderers[$id];
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

    public function renderer(string $id, mixed ...$args): RendererInterface
    {
        return new ($this->renderers[$id])(...$args);
    }

    public function logger(LoggerInterface $logger): void
    {
        $this->instances['logger'] = $logger;
    }
}
