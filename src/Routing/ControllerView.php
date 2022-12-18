<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Closure;
use ReflectionMethod;
use Conia\Chuck\Registry;
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
        protected Registry $registry,
        /** @var callable-array|string */
        array|string $view,
    ) {
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
            $this->controller = new $controllerName(...Reflect::controllerConstructorParams($controllerName, $request));

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

        return $this->controller->$method(...$this->getViewArgs(
            $this->request,
            Closure::fromCallable([$this->controller, $method]),
            $this->route->args(),
        ));
    }

    /** @param $filter ?class-string */
    public function attributes(string $filter = null): array
    {
        return $this->getAttributes(new ReflectionMethod($this->controller, $this->method), $filter);
    }
}
