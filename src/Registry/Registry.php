<?php

declare(strict_types=1);

namespace Conia\Chuck\Registry;

use Closure;
use Conia\Chuck\Exception\NotFoundException;
use Psr\Container\ContainerInterface;

/**
 * @psalm-type EntryArray = array<never, never>|array<string, Entry>
 */
class Registry implements ContainerInterface
{
    protected Resolver $resolver;

    /** @psalm-var EntryArray */
    protected array $entries = [];

    /** @psalm-var array<never, never>|array<non-empty-string, self> */
    protected array $tags = [];

    public function __construct(
        protected readonly ?ContainerInterface $container = null,
        protected readonly bool $autowire = true,
        protected readonly string $tag = '',
    ) {
        if ($container) {
            $this->add(ContainerInterface::class, $container);
            $this->add($container::class, $container);
        } else {
            $this->add(ContainerInterface::class, $this);
        }

        $this->add(Registry::class, $this);
        $this->resolver = new Resolver($this);
    }

    public function has(string $id): bool
    {
        return isset($this->entries[$id]) || $this->container?->has($id);
    }

    public function entry(string $id, string $paramName = ''): Entry
    {
        $paramName = $this->normalizeParameterName($paramName);

        return $this->entries[$id . $paramName];
    }

    public function get(string $id): mixed
    {
        $entry = $this->entries[$id] ?? null;

        if ($entry) {
            return $this->resolveEntry($entry);
        }

        if ($this->container && $this->container->has($id)) {
            return $this->container->get($id);
        }

        // Autowiring: $id does not exists as an entry in the registry
        if ($this->autowire && class_exists($id)) {
            return $this->resolver->autowire($id);
        }

        $message = empty($this->tag) ?
            'Unresolvable id: ' . $id :
            'Unresolvable tagged id: ' . $this->tag . '::' . $id;

        throw new NotFoundException($message);
    }

    /**
     * @psalm-param non-empty-string $id
     */
    public function add(
        string $id,
        mixed $value = null,
        string $paramName = '',
    ): Entry {
        $paramName = $this->normalizeParameterName($paramName);
        $entry = new Entry($id, $value ?? $id);
        $this->entries[$id . $paramName] = $entry;

        return $entry;
    }

    /** @psalm-param non-empty-string $tag */
    public function tag(string $tag): Registry
    {
        if (!isset($this->tags[$tag])) {
            $this->tags[$tag] = new self(tag: $tag);
        }

        return $this->tags[$tag];
    }

    public function new(string $id, mixed ...$args): object
    {
        $entry = $this->entries[$id] ?? null;

        if ($entry) {
            /** @var mixed */
            $value = $entry->definition();

            if (is_string($value)) {
                if (interface_exists($value)) {
                    return $this->new($value, ...$args);
                }

                if (class_exists($value)) {
                    /** @psalm-suppress MixedMethodCall */
                    return new $value(...$args);
                }
            }
        }

        if ($this->autowire && class_exists($id)) {
            /** @psalm-suppress MixedMethodCall */
            return new $id(...$args);
        }

        throw new NotFoundException('Cannot instantiate ' . $id);
    }

    public function getWithParamName(string $id, string $paramName): mixed
    {
        $paramName = $this->normalizeParameterName($paramName);

        // See if there's a entry with a bound parameter name:
        // e. g. '\Namespace\MyClass$myParameter'
        // If $paramName is emtpy an existing unbound entry should
        // be found on first try.
        return isset($this->entries[$id . $paramName]) ?
            $this->resolveEntry($this->entries[$id . $paramName]) :
            $this->get($id);
    }

    protected function reifyAndReturn(Entry $entry, mixed $value): mixed
    {
        if ($entry->shouldReify()) {
            $entry->set($value);
        }

        return $value;
    }

    protected function resolveEntry(Entry $entry): mixed
    {
        if ($entry->shouldReturnAsIs()) {
            return $entry->definition();
        }

        /** @var mixed - the current value, instantiated or definition */
        $value = $entry->get();

        if (is_string($value)) {
            if (class_exists($value)) {
                $args = $entry->getArgs();

                if (isset($args)) {
                    // Don't autowire if $args are given
                    if ($args instanceof Closure) {
                        return $this->reifyAndReturn($entry, $this->fromArgsClosure($value, $args));
                    }

                    return $this->reifyAndReturn($entry, $this->fromArgsArray($value, $args));
                }

                return $this->reifyAndReturn($entry, $this->resolver->autowire($value));
            }

            if (isset($this->entries[$value])) {
                return $this->get($value);
            }
        }

        if ($value instanceof Closure) {
            $args = $entry->getArgs();

            if (is_null($args)) {
                $args = $this->resolver->resolveCallableArgs($value);
            } elseif ($args instanceof Closure) {
                /** @var array<string, mixed> */
                $args = $args();
            }

            /** @var mixed */
            $result = $value(...$args);

            return $this->reifyAndReturn($entry, $result);
        }

        if (is_object($value)) {
            return $value;
        }

        throw new NotFoundException('Unresolvable id: ' . print_r($value, true));
    }

    /** @psalm-param class-string $class */
    protected function fromArgsArray(string $class, array $args): object
    {
        /** @psalm-suppress MixedMethodCall */
        return new $class(...$args);
    }

    /** @psalm-param class-string $class */
    protected function fromArgsClosure(string $class, Closure $callback): object
    {
        $args = $this->resolver->resolveCallableArgs($callback);

        /** @psalm-suppress MixedMethodCall */
        return new $class(...$callback(...$args));
    }

    protected function normalizeParameterName(string $paramName): string
    {
        if (empty($paramName)) {
            return $paramName;
        }

        $paramName = trim($paramName);

        return str_starts_with($paramName, '$') ? $paramName : '$' . $paramName;
    }
}
