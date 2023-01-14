<?php

declare(strict_types=1);

namespace Conia\Chuck\Registry;

use Closure;
use Conia\Chuck\Exception\ContainerException;
use Conia\Chuck\Exception\NotFoundException;
use ReflectionClass;
use ReflectionFunction;
use ReflectionFunctionAbstract;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionObject;
use ReflectionParameter;
use Throwable;

class Resolver
{
    public function __construct(protected readonly Registry $registry)
    {
    }

    /** @psalm-param class-string $class */
    public function autowire(string $class, array $predefinedArgs = []): object
    {
        if (!$this->registry->autowire) {
            try {
                $this->registry->new($class);
            } catch (Throwable $e) {
                throw new ContainerException(
                    "Autowiring is turned off. Tried to instantiate class '{$class}'"
                );
            }
        }

        $rc = new ReflectionClass($class);
        $constructor = $rc->getConstructor();
        $args = $this->resolveArgs($constructor, $predefinedArgs);

        try {
            return $this->resolveCallAttributes($rc->newInstance(...$args));
        } catch (Throwable $e) {
            throw new ContainerException(
                'Autowiring unresolvable: ' . $class . ' Details: ' . $e->getMessage()
            );
        }
    }

    public function resolveCallAttributes(object $instance): object
    {
        $callAttrs = (new ReflectionObject($instance))->getAttributes(Call::class);

        // See if the attribute itself has one or more Call attributes. If so,
        // resolve/autowire the arguments of the method it states and call it.
        foreach ($callAttrs as $callAttr) {
            $resolver = new Resolver($this->registry);
            $callAttr = $callAttr->newInstance();
            $methodToResolve = $callAttr->method;

            /** @psalm-var callable */
            $callable = [$instance, $methodToResolve];
            $args = $resolver->resolveCallableArgs($callable, $callAttr->args);
            $callable(...$args);
        }

        return $instance;
    }

    public function resolveParam(ReflectionParameter $param): mixed
    {
        $type = $param->getType();

        if ($type instanceof ReflectionNamedType) {
            try {
                return $this->registry->get(ltrim($type->getName(), '?'));
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

    /** @psalm-param callable-array|callable $callable */
    public function resolveCallableArgs(array|callable $callable, array $predefinedArgs = []): array
    {
        $callable = Closure::fromCallable($callable);
        $rf = new ReflectionFunction($callable);

        return $this->resolveArgs($rf, $predefinedArgs);
    }

    /** @psalm-param class-string $class */
    public function resolveConstructorArgs(string $class, array $predefinedArgs = []): array
    {
        $rc = new ReflectionClass($class);
        $constructor = $rc->getConstructor();

        return $this->resolveArgs($constructor, $predefinedArgs);
    }

    protected function resolveArgs(
        ?ReflectionFunctionAbstract $rf,
        array $predefinedArgs = [],
    ): array {
        $args = [];

        if ($rf) {
            foreach ($rf->getParameters() as $param) {
                $name = $param->getName();

                if (isset($predefinedArgs[$name])) {
                    /** @psalm-var list<mixed> */
                    $args[] = $predefinedArgs[$name];
                } else {
                    /** @psalm-var list<mixed> */
                    $args[] = $this->resolveParam($param);
                }
            }
        }

        return $args;
    }
}
