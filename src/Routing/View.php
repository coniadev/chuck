<?php

declare(strict_types=1);

namespace Chuck\Routing;

use \RuntimeException;
use \Throwable;
use Chuck\RequestInterface;
use Chuck\Util\Reflect;


abstract class View
{
    public static function get(RequestInterface $request, RouteInterface $route): View
    {
        $view = $route->view();

        if (is_callable($view)) {
            return new CallableView($request, $route, $view);
        } else {
            /**
             * @psalm-suppress PossiblyInvalidArgument
             *
             * According to Psalm, $view could be a Closure. But since we
             * checked for is_callable before, this can never happen.
             */
            return new ControllerView($request, $route, $view);
        }
    }

    abstract public function execute(): mixed;
    // abstract public function attributes(): array;

    /**
     * Determines the arguments passed to the view
     *
     * - If a view parameter implements RequestInterface, the request will be passed.
     * - If names of the view parameters match names of the route arguments
     *   it will try to convert the argument to the parameter type and add it to
     *   the returned args list.
     * - Only string, float, int and RequestInterface are supported.
     */
    protected function getViewArgs(
        RequestInterface $request,
        callable $view,
        array $routeArgs,
    ): array {
        $args = [];
        $rf = Reflect::getReflectionFunction($view);
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
                    default => Reflect::getRequestParamOrError($request, $param, $name),
                };
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
}
