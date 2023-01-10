<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\Exception\ContainerException;
use Conia\Chuck\Exception\NotFoundException;
use Psr\Container\ContainerInterface;
use ReflectionClass;
use ReflectionFunction;
use ReflectionFunctionAbstract;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionParameter;
use Throwable;

/**
 * @psalm-type EntryArray = array<never, never>|array<string, RegistryEntry>
 */
class Registry implements ContainerInterface
{
    /** @var EntryArray */
    protected array $entries = [];

    /** @var array<never, never>|array<string, EntryArray> */
    protected array $taggedEntries = [];

    public function __construct(
        protected readonly ?ContainerInterface $container = null,
        protected readonly bool $autowire = true
    ) {
        if ($container) {
            $this->add(ContainerInterface::class, $container);
            $this->add($container::class, $container);
        } else {
            $this->add(ContainerInterface::class, $this);
        }

        $this->add(Registry::class, $this);
    }

    public function has(string $id): bool
    {
        return isset($this->entries[$id]) || $this->container?->has($id);
    }

    public function entry(string $id, string $paramName = ''): mixed
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

        if ($this->container?->has($id)) {
            return $this->container->get($id);
        }

        // Autowiring: $id does not exists as an entry in the registry
        if ($this->autowire && class_exists($id)) {
            return $this->autowire($id);
        }

        throw new NotFoundException('Unresolvable id: ' . $id);
    }

    /**
     * @psalm-param non-empty-string $id
     */
    public function add(
        string $id,
        mixed $value = null,
        string $paramName = '',
    ): RegistryEntry {
        $paramName = $this->normalizeParameterName($paramName);
        $entry = new RegistryEntry($id, $value ?? $id);
        $this->entries[$id . $paramName] = $entry;

        return $entry;
    }

    public function tag(string $tag): RegistryTag
    {
        return new RegistryTag($tag, $this);
    }

    public function hasTagged(string $tag, string $id): bool
    {
        return isset($this->taggedEntries[$tag][$id]);
    }

    public function getTaggedEntry(string $tag, string $id): RegistryEntry
    {
        return $this->taggedEntries[$tag][$id];
    }

    public function getTagged(string $tag, string $id): mixed
    {
        $entry = $this->taggedEntries[$tag][$id] ?? null;

        if ($entry) {
            return $this->resolveEntry($entry);
        }

        throw new NotFoundException('Unresolvable tagged id: ' . $tag . '::' . $id);
    }

    /**
     * @psalm-param non-empty-string $id
     */
    public function addTagged(string $tag, string $id, mixed $value = null): RegistryEntry
    {
        $entry = new RegistryEntry($id, $value ?? $id);
        $this->taggedEntries[$tag][$id] = $entry;

        return $entry;
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

    public function resolveParam(ReflectionParameter $param): mixed
    {
        $type = $param->getType();

        if ($type instanceof ReflectionNamedType) {
            try {
                return $this->getWithParamName($type->getName(), '$' . ltrim($param->getName(), '?'));
            } catch (NotFoundException $e) {
                if ($param->isDefaultValueAvailable()) {
                    return $param->getDefaultValue();
                }

                throw $e;
            }
        } else {
            if ($type) {
                throw new ContainerException(
                    "Autowiring does not support union or intersection types. Source: \n" .
                        $this->getParamInfo($param)
                );
            }

            throw new ContainerException(
                "Autowired entities need to have typed constructor parameters. Source: \n" .
                    $this->getParamInfo($param)
            );
        }
    }

    public function getParamInfo(ReflectionParameter $param): string
    {
        $type = $param->getType();
        $rf = $param->getDeclaringFunction();
        $rc = null;

        if ($rf instanceof ReflectionMethod) {
            $rc = $rf->getDeclaringClass();
        }

        return ($rc ? $rc->getName() . '::' : '') .
            ($rf->getName() . '(..., ') .
            ($type ? (string)$type . ' ' : '') .
            '$' . $param->getName() . ', ...)';
    }

    protected function resolveEntry(RegistryEntry $entry): mixed
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

                return $this->reifyAndReturn($entry, $this->autowire($value));
            }

            if (isset($this->entries[$value])) {
                return $this->get($value);
            }
        }

        if ($value instanceof Closure) {
            // Get the instance from the registered closure
            $rf = new ReflectionFunction($value);
            $args = $entry->getArgs();

            if (is_null($args)) {
                $args = $this->resolveArgs($rf);
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

    protected function reifyAndReturn(RegistryEntry $entry, mixed $value): mixed
    {
        if ($entry->shouldReify()) {
            $entry->set($value);
        }

        return $value;
    }

    /** @psalm-param class-string $class */
    protected function autowire(string $class): object
    {
        $rc = new ReflectionClass($class);
        $constructor = $rc->getConstructor();
        $args = $this->resolveArgs($constructor);

        try {
            return $rc->newInstance(...$args);
        } catch (Throwable $e) {
            throw new ContainerException(
                'Autowiring unresolvable: ' . $class . ' Details: ' . $e->getMessage()
            );
        }
    }

    protected function resolveArgs(?ReflectionFunctionAbstract $rf): array
    {
        $args = [];

        if ($rf) {
            foreach ($rf->getParameters() as $param) {
                /** @var list<mixed> */
                $args[] = $this->resolveParam($param);
            }
        }

        return $args;
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
        $rf = new ReflectionFunction($callback);
        $args = $this->resolveArgs($rf);

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
