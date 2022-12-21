<?php

declare(strict_types=1);

namespace Conia\Chuck\View;

use Closure;
use ReflectionMethod;
use ReflectionClass;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Error\HttpServerError;
use Conia\Chuck\RequestInterface;
use Conia\Chuck\Routing\RouteInterface;
use Conia\Chuck\Util\Reflect;

class ControllerView extends View
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected array $attributes;
    protected object $controller;
    protected string $method;

    public function __construct(
        protected RequestInterface $request,
        protected RouteInterface $route,
        Registry $registry,
        /** @var callable-array|string */
        array|string $view,
    ) {
        $this->registry = $registry;

        if (is_array($view)) {
            [$controllerName, $method] = $view;
        } else {
            /** @var string $view */
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

        return $this->controller->$method(...$this->getArgs(
            Reflect::getReflectionFunction(
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
