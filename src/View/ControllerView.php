<?php

declare(strict_types=1);

namespace Conia\Chuck\View;

use Closure;
use ReflectionMethod;
use ReflectionClass;
use Conia\Chuck\Registry;
use Conia\Chuck\Exception\HttpServerError;
use Conia\Chuck\Request;
use Conia\Chuck\Routing\Route;

class ControllerView extends View
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected array $attributes;
    protected object $controller;
    protected string $method;

    public function __construct(
        protected Route $route,
        Registry $registry,
        /** @var string|list{string, string} */
        string|array $view,
    ) {
        $this->registry = $registry;

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
            $args = $constructor ? $this->getArgs($constructor, $this->route->args()) : [];
            $this->controller = $rc->newInstance(...$args);

            if (method_exists($this->controller, $method)) {
                $this->method = $method;
            } else {
                $view = $controllerName . '::' . $method;
                throw HttpServerError::withSubTitle("Controller method not found $view");
            }
        } else {
            throw HttpServerError::withSubTitle("Controller not found ${controllerName}");
        }
    }

    public function execute(): mixed
    {
        $method = $this->method;

        /**
         * We check in the constructor if this is a valid object and
         * if the method exists. We can safely suppress this.
         *
         * @psalm-suppress MixedMethodCall
         */
        return $this->controller->$method(...$this->getArgs(
            self::getReflectionFunction(
                Closure::fromCallable([$this->controller, $method])
            ),
            $this->route->args(),
        ));
    }

    /** @param $filter ?class-string */
    public function attributes(string $filter = null): array
    {
        return $this->getAttributes(new ReflectionMethod($this->controller, $this->method), $filter);
    }
}
