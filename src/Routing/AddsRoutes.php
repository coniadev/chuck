<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Closure;

trait AddsRoutes
{
    public function route(
        string $pattern,
        Closure|array|string $view,
        ?string $name = null,
        array $params = []
    ): Route {
        $route = new Route($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    public function get(string $pattern, Closure|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::get($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    public function post(string $pattern, Closure|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::post($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    public function put(string $pattern, Closure|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::put($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    public function patch(string $pattern, Closure|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::patch($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    public function delete(string $pattern, Closure|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::delete($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    public function head(string $pattern, Closure|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::head($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    public function options(string $pattern, Closure|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::options($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }
}
