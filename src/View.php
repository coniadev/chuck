<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use JsonException;
use ReflectionClass;
use ReflectionFunction;
use ReflectionFunctionAbstract;
use ReflectionMethod;
use ReflectionObject;
use Stringable;
use Throwable;
use Conia\Chuck\Attribute\Render;
use Conia\Chuck\Config;
use Conia\Chuck\Exception\HttpServerError;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Exception\UnresolvableException;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Routing\Route;

class View
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected array $attributes;
    protected readonly Closure $closure;

    public function __construct(
        callable|string|array $view,
        protected readonly array $routeArgs,
        protected readonly Registry $registry
    ) {
        if (is_callable($view)) {
            $this->closure = Closure::fromCallable($view);
        } else {
            $this->closure = $this->getClosure($view);
        }
    }

    public function execute(): mixed
    {
        /**
         * We check in the constructor if this is a valid object and
         * if the method exists. We can safely suppress this.
         *
         * @psalm-suppress MixedMethodCall
         */
        return ($this->closure)(...$this->getArgs(
            self::getReflectionFunction($this->closure),
            $this->routeArgs,
            $this->registry,
        ));
    }

    public function respond(
        Request $request,
        Route $route,
        Registry $registry,
        Config $config,
    ): Response {
        /**
         * @psalm-suppress MixedAssignment
         *
         * Later in the function we check the type of $result.
         * */
        $result = $this->execute($route->args(), $registry);

        if ($result instanceof Response) {
            return $result;
        } else {
            $rendererConfig = $route->getRenderer();

            if ($rendererConfig) {
                $renderer = $config->renderer(
                    $request,
                    $registry,
                    $rendererConfig->type,
                    ...$rendererConfig->args
                );

                return $renderer->response($result);
            }

            $renderAttributes = $this->attributes(Render::class);

            if (count($renderAttributes) > 0) {
                assert($renderAttributes[0] instanceof Render);
                return $renderAttributes[0]->response($request, $config, $registry, $result);
            }

            $responseFactory = new ResponseFactory($registry);

            if (is_string($result)) {
                return $responseFactory->html($result);
            } elseif ($result instanceof Stringable) {
                return $responseFactory->html($result->__toString());
            } else {
                try {
                    return $responseFactory->json($result);
                } catch (JsonException) {
                    throw new RuntimeException('Cannot determine a response handler for the return type of the view');
                }
            }
        }
    }

    protected function getClosure(array|string $view): Closure
    {
        if (is_array($view)) {
            [$controllerName, $method] = $view;
            assert(is_string($controllerName));
            assert(is_string($method));
        } else {
            if (!str_contains($view, '::')) {
                $view .= '::__invoke';
            }

            [$controllerName, $method] = explode('::', $view);
        }

        if (class_exists($controllerName)) {
            $rc = new ReflectionClass($controllerName);
            $constructor = $rc->getConstructor();
            $args = $constructor ? $this->getArgs(
                $constructor,
                $this->routeArgs,
                $this->registry
            ) : [];
            $controller = $rc->newInstance(...$args);

            if (method_exists($controller, $method)) {
                return Closure::fromCallable([$controller, $method]);
            } else {
                $view = $controllerName . '::' . $method;
                throw HttpServerError::withSubTitle("Controller method not found $view");
            }
        } else {
            throw HttpServerError::withSubTitle("Controller not found $controllerName");
        }
    }

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
    protected function getArgs(ReflectionFunctionAbstract $rf): array
    {
        /** @var array<string, mixed> */
        $args = [];
        $params = $rf->getParameters();
        $errMsg = 'View parameters cannot be resolved. Details: ';

        foreach ($params as $param) {
            $name = $param->getName();

            try {
                $args[$name] = match ((string)$param->getType()) {
                    'int' => is_numeric($this->routeArgs[$name]) ?
                        (int)$this->routeArgs[$name] :
                        throw new RuntimeException($errMsg . "Cannot cast '$name' to int"),
                    'float' => is_numeric($this->routeArgs[$name]) ?
                        (float)$this->routeArgs[$name] :
                        throw new RuntimeException($errMsg . "Cannot cast '$name' to float"),
                    'string' => $this->routeArgs[$name],
                    default => $this->registry->resolveParam($param),
                };
            } catch (UnresolvableException $e) {
                throw $e;
            } catch (Throwable $e) {
                // Check if the view parameter has a default value
                if (!array_key_exists($name, $this->routeArgs) && $param->isDefaultValueAvailable()) {
                    $args[$name] = $param->getDefaultValue();

                    continue;
                }

                throw new RuntimeException($errMsg . $e->getMessage());
            }
        }

        assert(count($params) === count($args));

        return $args;
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

    /** @param $filter ?class-string */
    public function attributes(string $filter = null): array
    {
        $reflector = new ReflectionFunction($this->closure);

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
