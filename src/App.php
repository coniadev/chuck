<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Error\Handler;


class App
{
    protected RouterInterface $router;
    protected ConfigInterface $config;

    public function __construct(protected RequestInterface $request)
    {
        $this->config = $request->getConfig();
        $this->router = $request->getRouter();
    }

    public static function create(array|ConfigInterface $options): self
    {
        if ($options instanceof ConfigInterface) {
            $config = $options;
        } else {
            $config = new Config($options);
        }

        $router = new Router();
        /** @var RequestInterface */
        $request = $config->registry->new(RequestInterface::class, $config, $router);

        $errorHandler = new Handler($request);
        $errorHandler->setup();

        $app = new self($request);

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

    public function route(RouteInterface $route): void
    {
        $this->router->addRoute($route);
    }

    public function staticRoute(
        string $name,
        string $prefix,
        string $path,
    ): void {
        $this->router->addStatic($name, $prefix, $path);
    }

    public function middleware(object|string $middleware): void
    {
        $this->router->middleware($middleware);
    }

    public function register(string $interface, string $class): void
    {
        $this->config->registry->add($interface, $class);
    }

    public function renderer(string $name, string $class): void
    {
        $this->config->addRenderer($name, $class);
    }

    public function run(bool $emit = true): ResponseInterface
    {
        $response = $this->router->dispatch($this->request);

        if ($emit) {
            $response->emit();
        }

        return $response;
    }
}
