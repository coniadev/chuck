<?php

declare(strict_types=1);

namespace Conia\Chuck\View;

use ReflectionAttribute;
use ReflectionFunction;
use ReflectionFunctionAbstract;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionParameter;
use RuntimeException;
use Throwable;
use Conia\Chuck\Error\UntypedViewParameter;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\RequestInterface;
use Conia\Chuck\Routing\RouteInterface;
use Conia\Chuck\Util\Reflect;

abstract class View
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected array $attributes;
    protected Registry $registry;

    public static function get(
        RequestInterface $request,
        RouteInterface $route,
        Registry $registry,
    ): View {
        $view = $route->view();

        if (is_callable($view)) {
            return new CallableView($request, $route, $registry, $view);
        } else {
            /**
             * @psalm-suppress PossiblyInvalidArgument
             *
             * According to Psalm, $view could be a Closure. But since we
             * checked for is_callable before, this can never happen.
             */
            return new ControllerView($request, $route, $registry, $view);
        }
    }

    abstract public function execute(): mixed;
    /** @param $filter ?class-string */
    abstract public function attributes(string $filter = null): array;

    protected function resolve(ReflectionParameter $param): mixed
    {
        $type = $param->getType();

        if ($type === null) {
            throw new UntypedViewParameter('View paramters must provide a type');
        }

        return $this->registry->resolve((string)$type);
    }

    /**
     * Determines the arguments passed to the view and/or controller constructor
     *
     * - If a view parameter implements RequestInterface, the request will be passed.
     * - If names of the view parameters match names of the route arguments
     *   it will try to convert the argument to the parameter type and add it to
     *   the returned args list.
     * - Only string, float, int and RequestInterface are supported.
     */
    protected function getArgs(
        ReflectionFunction|ReflectionMethod $rf,
        array $routeArgs,
    ): array {
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
                    default => $this->resolve($param),
                };
            } catch (UntypedViewParameter $e) {
                throw $e;
            } catch (Throwable $e) {
                // Check if the view parameter has a default value
                if (!array_key_exists($name, $routeArgs) && $param->isOptional()) {
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
}
