<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\Response\ResponseInterface;
use Conia\Chuck\Registry\Entry;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Routing\{Route, Group, Router, AddsRoutes};

/** @psalm-consistent-constructor */
class App
{
    use AddsRoutes;

    public function __construct(
        private Request $request,
        private Config $config,
        private Router $router,
        private Registry $registry,
    ) {
        $registry->add(Request::class, $request);
        $registry->add($request::class, $request);
        $registry->add(Config::class, $config);
        $registry->add($config::class, $config);
        $registry->add(Router::class, $router);
        $registry->add($router::class, $router);
        $registry->add(App::class, $this);

        // Self register Registry for autowiring
        $registry->add($registry::class, $registry);
    }

    public static function create(Config $config): static
    {
        $registry = new Registry();
        $router = new Router();
        $request = new Request();

        $errorHandler = new ErrorHandler($config);
        $errorHandler->setup();

        $app = new static($request, $config, $router, $registry);

        return $app;
    }

    public function request(): Request
    {
        return $this->request;
    }

    public function router(): Router
    {
        return $this->router;
    }

    public function config(): Config
    {
        return $this->config;
    }

    public function registry(): Registry
    {
        return $this->registry;
    }

    public function addRoute(Route $route): void
    {
        $this->router->addRoute($route);
    }

    public function addGroup(Group $group): void
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

    /**
     * @param MiddlewareInterface|callable(
     *     Request,
     *     callable
     * ):\Conia\Chuck\Response\ResponseInterface $middlewares
     *
     * TODO: Why can't we import the custom psalm type MiddlewareCallable from MiddlewareInterface
     */
    public function middleware(MiddlewareInterface|callable ...$middlewares): void
    {
        $this->router->middleware(...$middlewares);
    }

    /**
     * @param non-empty-string $key
     * @param object|class-string $value
     * */
    public function register(string $key, object|string $value): Entry
    {
        return $this->registry->add($key, $value);
    }

    public function run(): ResponseInterface
    {
        $response = $this->router->dispatch($this->request, $this->config, $this->registry);
        $response->emit();

        return $response;
    }
}
