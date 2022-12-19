<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Throwable;
use OutOfBoundsException;
use ReflectionClass;
use Conia\Chuck\Error\Unresolvable;
use Conia\Chuck\Error\UntypedResolveParameter;

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

    public function resolve(string $id, string $path = ''): object
    {
        if ($this->has($id)) {
            $entry = $this->get($id);

            if (is_object($entry)) {
                return $entry;
            }

            if (is_string($entry) && $entry !== $id) {
                return $this->resolve($entry, $id . ' -> ');
            }
        }

        if (class_exists($id)) {
            $reflectionClass = new ReflectionClass($id);
            $constructor = $reflectionClass->getConstructor();
            $params = [];

            if ($constructor) {
                foreach ($constructor->getParameters() as $param) {
                    $type = $param->getType();

                    if ($type === null) {
                        throw new UntypedResolveParameter(
                            'Autowired classes need to have typed constructor parameters. ' .
                            'Resolve path: ' .
                            $path . $id . '::' .
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
                    'Autowiring unresolvable: ' . $path . $id . ' Details: ' . $e->getMessage()
                );
            }
        }

        throw new Unresolvable('Autowiring unresolvable: ' . $path . $id);
    }
}
