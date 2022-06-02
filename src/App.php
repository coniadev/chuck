<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Error\Handler;
use Chuck\Logger;
use Chuck\Routing\GroupInterface;
use Chuck\Routing\RouteInterface;
use Chuck\Routing\{Router, RouterInterface};


class App
{
    protected RegistryInterface $registry;

    public function __construct(
        protected RequestInterface $request,
        protected ConfigInterface $config,
        protected RouterInterface $router,
    ) {
        $this->registry = $request->getRegistry();
    }

    public static function create(
        ConfigInterface $config,
        RegistryInterface $registry = new Registry(),
    ): static {
        $registry->logger(new Logger(
            $config->log()->level,
            $config->log()->file,
        ));

        $router = new Router();
        $request = new Request($config, $router, $registry);

        if (PHP_SAPI !== 'cli') {
            $errorHandler = new Handler($request);
            $errorHandler->setup();
        }

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

    public function registry(): RegistryInterface
    {
        return $this->registry;
    }

    public function add(RouteInterface $route): void
    {
        $this->router->addRoute($route);
    }

    public function group(GroupInterface $group): void
    {
        $group->create($this->router);
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

    /**
     * @param string|class-string $key
     * @param object|class-string $entry
     */
    public function register(string $id, string|object $entry): void
    {
        $this->registry->add($id, $entry);
    }

    public function run(): ResponseInterface
    {
        $response = $this->router->dispatch($this->request);
        $response->emit();

        return $response;
    }
}
