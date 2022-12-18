<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\Error\Handler;
use Conia\Chuck\Response\ResponseInterface;
use Conia\Chuck\Routing\GroupInterface;
use Conia\Chuck\Routing\RouteInterface;
use Conia\Chuck\Routing\{Group, Router, RouterInterface, AddsRoutes};

/** @psalm-consistent-constructor */
class App
{
    use AddsRoutes;

    public function __construct(
        private RequestInterface $request,
        private ConfigInterface $config,
        private RouterInterface $router,
        private Registry $registry,
    ) {
        $registry->add(RequestInterface::class, $request);
        $registry->add($request::class, $request);
        $registry->add(ConfigInterface::class, $config);
        $registry->add($config::class, $config);
        $registry->add(RouterInterface::class, $router);
        $registry->add($router::class, $router);
    }

    public static function create(ConfigInterface $config): static
    {
        $registry = new Registry();
        $router = new Router();
        $request = new Request($config);

        $errorHandler = new Handler($request);
        $errorHandler->setup();

        $app = new static($request, $config, $router, $registry);

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

    public function addGroup(GroupInterface $group): void
    {
        $this->router->addGroup($group);
    }

    public function group(
        string $patternPrefix,
        Closure $createClosure,
        ?string $namePrefix = null,
    ): Group {
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

    public function register(string $key, mixed $value = null): void
    {
        $this->registry->add($key, $value);
    }

    public function run(): ResponseInterface
    {
        $response = $this->router->dispatch($this->request);
        $response->emit();

        return $response;
    }
}
