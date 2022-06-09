<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Error\Handler;
use Chuck\Routing\GroupInterface;
use Chuck\Routing\RouteInterface;
use Chuck\Routing\{Router, RouterInterface};


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

    public function add(RouteInterface $route): void
    {
        $this->router->addRoute($route);
    }

    public function group(GroupInterface $group): void
    {
        $this->router->addGroup($group);
    }

    public function static(
        string $name,
        string $prefix,
        string $path,
    ): void {
        $this->router->addStatic($name, $prefix, $path);
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
