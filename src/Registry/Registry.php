<?php

declare(strict_types=1);

namespace Conia\Chuck\Registry;

use Closure;
use OutOfBoundsException;
use ReflectionClass;
use ReflectionFunction;
use ReflectionFunctionAbstract;
use ReflectionNamedType;
use ReflectionParameter;
use RuntimeException;
use Throwable;
use Conia\Chuck\Error\Unresolvable;
use Conia\Chuck\Error\UntypedResolveParameter;
use Conia\Chuck\Error\UnsupportedResolveParameter;

class Registry
{
    protected array $entries = [];

    public function add(
        string $id,
        object|string $value,
        string $paramName = '',
    ): Entry {
        $paramName = trim($paramName);

        if ($id === $value) {
            throw new RuntimeException('Registry::add argument $id must be different from $value');
        }

        $entry = new Entry($id, $value, $paramName);
        $this->entries[$id . $paramName] = $entry;

        return $entry;
    }


    public function has(string $id): bool
    {
        return isset($this->entries[$id]);
    }

    public function get(string $id): mixed
    {
        try {
            return $this->entries[$id]->value();
        } catch (Throwable $e) {
            throw new OutOfBoundsException("Undefined registry key \"$id\" " . $e->getMessage());
        }
    }

    public function new(string $id, mixed ...$args): object
    {
        return new ($this->get($id))(...$args);
    }

    public function resolve(string $id, string $paramName = ''): object
    {
        $paramName = $paramName ?
            (str_starts_with($paramName, '$') ? $paramName : '$'. $paramName) :
            '';
        // 1. See if there's a entry with a bound parameter name:
        //    e. g. '\Namespace\MyClass$myParameter'
        //    If $paramName is emtpy an existing unbound entry should
        //    be found on first try.
        // 2. See if there is an unbound entry:
        //    e. g. '\Namespace\MyClass'
        $entry = $this->entries[$id . $paramName] ??
            $this->entries[$id] ??
            null;

        if ($entry) {
            return $this->resolveEntry($entry);
        }

        // Autowiring: $id does not exists as an entry in the registry
        if (class_exists($id)) {
            return $this->autowire($id);
        }

        throw new Unresolvable('Autowiring unresolvable: ' . $id);
    }

    protected function resolveEntry(Entry $entry): object
    {
        $value = $entry->value();

        if ($value instanceof Closure) {
            // Get the instance from the registered closure
            $rf = new ReflectionFunction($value);
            $args = $this->resolveArgs($rf);

            return $this->reifyAndReturn($entry, $value(...$args));
        }

        if (is_object($value)) {
            // Already an instance, no need to reify
            return $value;
        }

        // As $value is a string $id is likly to be a
        // interface or abstract/base class
        $args = $entry->getArgs();

        if (isset($args)) {
            // Don't autowire if $args are given
            if ($args instanceof Closure) {
                return $this->reifyAndReturn($entry, $this->fromArgsClosure($value, $args));
            }

            return $this->reifyAndReturn($entry, $this->fromArgsArray($value, $args));
        }

        // $value is a string, no args given for the entry
        return $this->reifyAndReturn($entry, $this->resolve($value));
    }

    protected function reifyAndReturn(Entry $entry, object $value): object
    {
        if ($entry->shouldReify()) {
            $entry->update($value);
        }

        return $value;
    }

    public function resolveParam(ReflectionParameter $param): object
    {
        $type = $param->getType();

        if ($type instanceof ReflectionNamedType) {
            return $this->resolve($type->getName(), '$' . $param->getName());
        } else {
            if ($type) {
                throw new UnsupportedResolveParameter(
                    "Autowiring does not support union or intersection types.\nSource: " .
                    $this->getParamInfo($param)
                );
            } else {
                throw new UntypedResolveParameter(
                    "Autowired classes need to have typed constructor parameters.\nSource: " .
                    $this->getParamInfo($param)
                );
            }
        }
    }

    protected function getParamInfo(ReflectionParameter $param): string
    {
        $type = $param->getType();
        $rf = $param->getDeclaringFunction();
        $rc = $rf->getDeclaringClass();

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
            throw new Unresolvable(
                'Autowiring unresolvable: ' . $class . ' Details: ' . $e->getMessage()
            );
        }
    }

    protected function resolveArgs(?ReflectionFunctionAbstract $rf): array
    {
        $args = [];

        if ($rf) {
            foreach ($rf->getParameters() as $param) {
                $args[] = $this->resolveParam($param);
            }
        }

        return $args;
    }

    /** @param class-string $class */
    protected function fromArgsArray(string $class, array $args): object
    {
        return new $class(...$args);
    }

    /** @param class-string $class */
    protected function fromArgsClosure(string $class, Closure $callback): object
    {
        $rf = new ReflectionFunction($callback);
        $args = $this->resolveArgs($rf);

        return new $class(...$callback(...$args));
    }
}
