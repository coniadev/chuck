<?php

declare(strict_types=1);

namespace Conia\Chuck\View;

use Closure;
use ReflectionFunction;
use ReflectionMethod;
use ReflectionObject;
use ReflectionFunctionAbstract;
use Throwable;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Exception\UnresolvableException;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Routing\Route;

abstract class View
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected array $attributes;
    protected Registry $registry;

    public static function get(
        Route $route,
        Registry $registry,
    ): View {
        $view = $route->view();

        if (is_callable($view)) {
            return new CallableView($route, $registry, $view);
        } else {
            /**
             * @psalm-suppress PossiblyInvalidArgument
             *
             * According to Psalm, $view could be a Closure. But since we
             * checked for is_callable before, this can never happen.
             */
            return new ControllerView($route, $registry, $view);
        }
    }

    abstract public function execute(): mixed;
    /** @param $filter ?class-string */
    abstract public function attributes(string $filter = null): array;

    /**
     * Determines the arguments passed to the view and/or controller constructor
     *
     * - If a view parameter implements Request, the request will be passed.
     * - If names of the view parameters match names of the route arguments
     *   it will try to convert the argument to the parameter type and add it to
     *   the returned args list.
     * - If the parameter is typed, try to resolve it via registry or
     *   autowiring.
     * - Otherwise fail.
     *
     * @psalm-suppress MixedAssignment -- $args values are mixed
     */
    protected function getArgs(
        ReflectionFunctionAbstract $rf,
        array $routeArgs,
    ): array {
        /** @var array<string, mixed> */
        $args = [];
        $params = $rf->getParameters();
        $errMsg = 'View parameters cannot be resolved. Details: ';

        foreach ($params as $param) {
            $name = $param->getName();

            try {
                $args[$name] = match ((string)$param->getType()) {
                    'int' => is_numeric($routeArgs[$name]) ?
                        (int)$routeArgs[$name] :
                        throw new RuntimeException($errMsg . "Cannot cast '$name' to int"),
                    'float' => is_numeric($routeArgs[$name]) ?
                        (float)$routeArgs[$name] :
                        throw new RuntimeException($errMsg . "Cannot cast '$name' to float"),
                    'string' => $routeArgs[$name],
                    default => $this->registry->resolveParam($param),
                };
            } catch (UnresolvableException $e) {
                throw $e;
            } catch (Throwable $e) {
                // Check if the view parameter has a default value
                if (!array_key_exists($name, $routeArgs) && $param->isDefaultValueAvailable()) {
                    $args[$name] = $param->getDefaultValue();

                    continue;
                }

                throw new RuntimeException($errMsg . $e->getMessage());
            }
        }

        assert(count($params) === count($args));

        return $args;
    }

    /** @param $filter class-string */
    protected function getAttributes(ReflectionFunctionAbstract $reflector, string $filter = null): array
    {
        /** @psalm-suppress RedundantPropertyInitializationCheck */
        if (!isset($this->attributes)) {
            $this->attributes = array_map(function ($attribute) {
                return $attribute->newInstance();
            }, $reflector->getAttributes());
        }

        if ($filter) {
            return array_filter($this->attributes, function ($attribute) use ($filter) {
                return $attribute instanceof $filter;
            });
        }

        return $this->attributes;
    }

    public static function getReflectionFunction(
        callable $callable
    ): ReflectionFunction|ReflectionMethod {
        if ($callable instanceof Closure) {
            return new ReflectionFunction($callable);
        } elseif (is_object($callable)) {
            return (new ReflectionObject($callable))->getMethod('__invoke');
        } else {
            /** @var Closure|non-falsy-string $callable */
            return new ReflectionFunction($callable);
        }
    }
}
