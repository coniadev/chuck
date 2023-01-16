<?php

declare(strict_types=1);

namespace Conia\Chuck\Http;

use Closure;
use Conia\Chuck\Di\Resolver;
use Conia\Chuck\Exception\ContainerException;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Psr\Factory;
use Conia\Chuck\Registry;
use Conia\Chuck\Renderer\Config as RendererConfig;
use Conia\Chuck\Renderer\Render;
use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Response;
use Conia\Chuck\Route;
use Psr\Http\Message\ResponseInterface as PsrResponse;
use ReflectionAttribute;
use ReflectionClass;
use ReflectionFunction;
use ReflectionFunctionAbstract;
use ReflectionMethod;
use ReflectionObject;
use Throwable;

class View
{
    protected ?array $attributes = null;
    protected Closure $closure;

    public function __construct(
        callable|string|array $view,
        protected readonly array $routeArgs,
        protected readonly Registry $registry
    ) {
        if (is_callable($view)) {
            /** @var callable $view -- Psalm complains even though we use is_callable() */
            $this->closure = Closure::fromCallable($view);
        } else {
            $this->closure = $this->getClosure($view);
        }
    }

    public function execute(): mixed
    {
        return ($this->closure)(...$this->getArgs(
            self::getReflectionFunction($this->closure)
        ));
    }

    public function respond(
        Route $route,
        Registry $registry,
    ): Response {
        /**
         * @psalm-suppress MixedAssignment
         *
         * Later in the function we check the type of $result.
         */
        $result = $this->execute();

        if ($result instanceof Response) {
            return $result;
        }

        if ($result instanceof PsrResponse) {
            $factory = $registry->get(Factory::class);
            assert($factory instanceof Factory);

            return new Response($result, $factory);
        }

        $renderAttributes = $this->attributes(Render::class);

        if (count($renderAttributes) > 0) {
            assert($renderAttributes[0] instanceof Render);

            return $renderAttributes[0]->response($registry, $result);
        }

        $rendererConfig = $route->getRenderer();

        if ($rendererConfig) {
            return $this->respondFromRenderer($registry, $rendererConfig, $result);
        }

        throw new RuntimeException('Unable to determine a response handler for the returned value of the view');
    }

    public static function getReflectionFunction(
        callable $callable
    ): ReflectionFunction|ReflectionMethod {
        if ($callable instanceof Closure) {
            return new ReflectionFunction($callable);
        }
        if (is_object($callable)) {
            return (new ReflectionObject($callable))->getMethod('__invoke');
        }
        /** @var Closure|non-falsy-string $callable */
        return new ReflectionFunction($callable);
    }

    /** @psalm-param $filter ?class-string */
    public function attributes(string $filter = null): array
    {
        $reflector = new ReflectionFunction($this->closure);

        if (!isset($this->attributes)) {
            $this->attributes = array_map(function ($attribute) {
                return $this->newAttributeInstance($attribute);
            }, $reflector->getAttributes());
        }

        if ($filter) {
            return array_values(
                array_filter($this->attributes, function ($attribute) use ($filter) {
                    return $attribute instanceof $filter;
                })
            );
        }

        return $this->attributes;
    }

    protected function newAttributeInstance(ReflectionAttribute $attribute): object
    {
        return (new Resolver($this->registry))
            ->resolveCallAttributes($attribute->newInstance());
    }

    protected function respondFromRenderer(
        Registry $registry,
        RendererConfig $rendererConfig,
        mixed $result,
    ): Response {
        $renderer = $registry->tag(Renderer::class)->get($rendererConfig->type);
        assert($renderer instanceof Renderer);

        return $renderer->response($result, ...$rendererConfig->args);
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
            $args = $constructor ? $this->getArgs($constructor) : [];
            $controller = $rc->newInstance(...$args);

            if (method_exists($controller, $method)) {
                return Closure::fromCallable([$controller, $method]);
            }
            $view = $controllerName . '::' . $method;

            throw new RuntimeException("View method not found {$view}");
        }

        throw new RuntimeException("Controller not found {$controllerName}");
    }

    /**
     * Determines the arguments passed to the view and/or controller constructor.
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
                        throw new RuntimeException($errMsg . "Cannot cast '{$name}' to int"),
                    'float' => is_numeric($this->routeArgs[$name]) ?
                        (float)$this->routeArgs[$name] :
                        throw new RuntimeException($errMsg . "Cannot cast '{$name}' to float"),
                    'string' => $this->routeArgs[$name],
                    default => (new Resolver($this->registry))->resolveParam($param),
                };
            } catch (ContainerException $e) {
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
}
