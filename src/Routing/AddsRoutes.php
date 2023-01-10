<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

/**
 * @psalm-import-type View from \Conia\Chuck\Routing\Route
 */
trait AddsRoutes
{
    abstract public function addRoute(Route $route): void;

    /** @psalm-param View $view */
    public function route(
        string $pattern,
        callable|array|string $view,
        ?string $name = null,
        array $params = []
    ): Route {
        $route = new Route($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    /** @psalm-param View $view */
    public function get(
        string $pattern,
        callable|array|string $view,
        ?string $name = null,
        array $params = []
    ): Route {
        $route = Route::get($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    /** @psalm-param View $view */
    public function post(
        string $pattern,
        callable|array|string $view,
        ?string $name = null,
        array $params = []
    ): Route {
        $route = Route::post($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    /** @psalm-param View $view */
    public function put(
        string $pattern,
        callable|array|string $view,
        ?string $name = null,
        array $params = []
    ): Route {
        $route = Route::put($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    /** @psalm-param View $view */
    public function patch(
        string $pattern,
        callable|array|string $view,
        ?string $name = null,
        array $params = []
    ): Route {
        $route = Route::patch($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    /** @psalm-param View $view */
    public function delete(
        string $pattern,
        callable|array|string $view,
        ?string $name = null,
        array $params = []
    ): Route {
        $route = Route::delete($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    /** @psalm-param View $view */
    public function head(
        string $pattern,
        callable|array|string $view,
        ?string $name = null,
        array $params = []
    ): Route {
        $route = Route::head($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }

    /** @psalm-param View $view */
    public function options(
        string $pattern,
        callable|array|string $view,
        ?string $name = null,
        array $params = []
    ): Route {
        $route = Route::options($pattern, $view, $name, $params);
        $this->addRoute($route);

        return $route;
    }
}
