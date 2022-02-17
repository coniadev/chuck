<?php

declare(strict_types=1);

namespace Chuck;

use \Closure;


class App
{
    protected RouterInterface $router;
    protected ConfigInterface $config;
    protected callable $localeNegotiatorClosure;

    public function __construct(protected RequestInterface $request)
    {
        $this->router = $request->getRouter();
        $this->config = $request->getConfig();
    }

    public static function create(array $settings): self
    {
        $config = new Config($settings);
        $router = new Router();
        $app = new self(new Request($config, $router));

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

    public function middleware(Closure|object|string $middleware): void
    {
        $this->router->middleware($middleware);
    }

    public function register(string $interface, string $class): void
    {
        $this->config->register($interface, $class);
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
