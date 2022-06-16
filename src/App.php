<?php

declare(strict_types=1);

namespace Chuck;

use \Closure;
use Chuck\Error\Handler;
use Chuck\Response\ResponseInterface;
use Chuck\Routing\GroupInterface;
use Chuck\Routing\RouteInterface;
use Chuck\Routing\{Group, Route, Router, RouterInterface};


/** @psalm-consistent-constructor */
class App
{
    public function __construct(
        protected RequestInterface $request,
        protected ConfigInterface $config,
        protected RouterInterface $router,
    ) {
    }

    public static function create(
        ConfigInterface $config,
    ): static {
        $router = new Router();
        $request = new Request($config, $router);

        $errorHandler = new Handler($request);
        $errorHandler->setup();

        $app = new static($request, $config, $router);

        return $app;
    }

    public function request(): RequestInterface
    {
        return $this->request;
    }

    public function router(): RouterInterface
    {
        return $this->router;
    }

    public function config(): ConfigInterface
    {
        return $this->config;
    }

    public function addRoute(RouteInterface $route): void
    {
        $this->router->addRoute($route);
    }

    public function route(string $pattern, callable|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = new Route($pattern, $view, $name, $params);
        $this->router->addRoute($route);

        return $route;
    }

    public function get(string $pattern, callable|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::get($pattern, $view, $name, $params);
        $this->router->addRoute($route);

        return $route;
    }

    public function post(string $pattern, callable|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::post($pattern, $view, $name, $params);
        $this->router->addRoute($route);

        return $route;
    }

    public function put(string $pattern, callable|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::put($pattern, $view, $name, $params);
        $this->router->addRoute($route);

        return $route;
    }

    public function patch(string $pattern, callable|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::patch($pattern, $view, $name, $params);
        $this->router->addRoute($route);

        return $route;
    }

    public function delete(string $pattern, callable|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::delete($pattern, $view, $name, $params);
        $this->router->addRoute($route);

        return $route;
    }

    public function head(string $pattern, callable|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::head($pattern, $view, $name, $params);
        $this->router->addRoute($route);

        return $route;
    }

    public function options(string $pattern, callable|array|string $view, ?string $name = null, array $params = []): Route
    {
        $route = Route::options($pattern, $view, $name, $params);
        $this->router->addRoute($route);

        return $route;
    }

    public function addGroup(GroupInterface $group): void
    {
        $this->router->addGroup($group);
    }

    public function group(
        string $patternPrefix,
        Closure $createClosure,
        ?string $namePrefix = null,
    ): GroupInterface {
        $group = new Group($patternPrefix, $createClosure, $namePrefix);
        $this->router->addGroup($group);

        return $group;
    }

    public function staticRoute(
        string $prefix,
        string $path,
        ?string $name = null,
    ): void {
        $this->router->addStatic($prefix, $path, $name);
    }

    public function middleware(callable ...$middlewares): void
    {
        $this->router->addMiddleware(...$middlewares);
    }

    public function run(): ResponseInterface
    {
        $response = $this->router->dispatch($this->request);
        $response->emit();

        return $response;
    }
}
