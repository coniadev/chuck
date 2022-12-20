<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Throwable;
use OutOfBoundsException;
use RuntimeException;
use ReflectionClass;
use Conia\Chuck\Error\Unresolvable;
use Conia\Chuck\Error\UntypedResolveParameter;

class Registry
{
    protected array $entries = [];

    public function add(
        string $abstract,
        object|string|null $concrete = null,
        string $with = '',
    ): void {
        $with = trim($with);
        $entry = new RegistryEntry($abstract, $concrete, $with);
        $this->entries[$abstract . $with] = $entry;

        return $entry;
    }


    public function has(string $abstract): bool
    {
        return isset($this->entries[$abstract]) || array_key_exists($abstract, $this->entries);
    }

    public function get(string $abstract): mixed
    {
        if (isset($this->entries[$abstract]) || array_key_exists($abstract, $this->entries)) {
            return $this->entries[$abstract];
        }

        throw new OutOfBoundsException("Undefined registry key \"$abstract\"");
    }

    public function new(string $abstract, mixed ...$args): object
    {
        return new ($this->get($abstract))(...$args);
    }

    public function resolve(string $abstract, string $path = ''): object
    {
        if ($this->has($abstract)) {
            $concrete = $this->get($abstract);

            if (is_object($concrete)) {
                return $concrete;
            }

            if (is_string($concrete) && $concrete !== $abstract) {
                return $this->resolve($concrete, $abstract . ' -> ');
            }
        }

        if (class_exists($abstract)) {
            $reflectionClass = new ReflectionClass($abstract);
            $constructor = $reflectionClass->getConstructor();
            $params = [];

            if ($constructor) {
                foreach ($constructor->getParameters() as $param) {
                    $type = $param->getType();

                    if ($type === null) {
                        throw new UntypedResolveParameter(
                            'Autowired classes need to have typed constructor parameters. ' .
                            'Resolve path: ' .
                            $path . $abstract . '::' .
                            $param->getName()
                        );
                    }

                    $params[] = $this->resolve((string)$type);
                }
            }

            try {
                return $reflectionClass->newInstance(...$params);
            } catch (Throwable $e) {
                throw new Unresolvable(
                    'Autowiring unresolvable: ' . $path . $abstract . ' Details: ' . $e->getMessage()
                );
            }
        }

        throw new Unresolvable('Autowiring unresolvable: ' . $path . $abstract);
    }
}
