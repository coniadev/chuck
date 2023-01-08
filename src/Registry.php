<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use ReflectionClass;
use ReflectionFunction;
use ReflectionFunctionAbstract;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionParameter;
use Throwable;
use Conia\Chuck\Exception\ContainerException;
use Conia\Chuck\Exception\NotFoundException;
use Psr\Container\ContainerInterface;

class Registry implements ContainerInterface
{
    /** @var array<never, never>|array<string, Entry> */
    protected array $entries = [];
    protected readonly ?ContainerInterface $container;

    public function __construct(
        ?ContainerInterface $container = null,
        protected readonly bool $autowire = true
    ) {
        $this->container = $container;

        if ($container) {
            $this->addAnyway(ContainerInterface::class, $container);
            $this->addAnyway($container::class, $container);
        } else {
            $this->addAnyway(ContainerInterface::class, $this);
        }

        $this->addAnyway(Registry::class, $this);
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
     * @param non-empty-string $id
     */
    public function add(
        string $id,
        mixed $value,
        string $paramName = '',
    ): Entry {
        if ($this->container) {
            throw new ContainerException('External container implementation used');
        }

        return $this->addAnyway($id, $value, $paramName);
    }

    /**
     * @param non-empty-string $id
     */
    public function addAnyway(
        string $id,
        mixed $value,
        string $paramName = '',
    ): Entry {
        $paramName = $this->normalizeParameterName($paramName);

        if ($id === $value) {
            throw new ContainerException('Registry::add argument $id must be different from $value');
        }

        $entry = new Entry($id, $value);
        $this->entries[$id . $paramName] = $entry;

        return $entry;
    }

    public function new(string $id, mixed ...$args): object
    {
        $entry = $this->entries[$id] ?? null;

        if ($entry) {
            /** @var mixed */
            $value = $entry->value();

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

    protected function resolveEntry(Entry $entry): mixed
    {
        /** @var mixed */
        $value = $entry->value();

        if ($entry->shouldReturnAsIs()) {
            return $value;
        }

        if (is_string($value)) {
            if (isset($this->entries[$value])) {
                return $this->get($value);
            }

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
        }

        if ($value instanceof Closure) {
            // Get the instance from the registered closure
            $rf = new ReflectionFunction($value);
            $args = [];

            if (func_num_args() === 1) {
                $args = $this->resolveArgs($rf);
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

    protected function reifyAndReturn(Entry $entry, mixed $value): mixed
    {
        if ($entry->shouldReify()) {
            $entry->update($value);
        }

        return $value;
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
            } else {
                throw new ContainerException(
                    "Autowired entities need to have typed constructor parameters. Source: \n" .
                        $this->getParamInfo($param)
                );
            }
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

    /** @param class-string $class */
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

    /** @param class-string $class */
    protected function fromArgsArray(string $class, array $args): object
    {
        /** @psalm-suppress MixedMethodCall */
        return new $class(...$args);
    }

    /** @param class-string $class */
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
