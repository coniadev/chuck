<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Error\HandlerInterface;
use Chuck\Error\Handler;


class App
{
    protected RouterInterface $router;
    protected ConfigInterface $config;

    public function __construct(
        protected RequestInterface $request,
        HandlerInterface $errorHandler = null,
        bool $forceErrorHandler = false,
    ) {
        $this->config = $request->getConfig();

        if (PHP_SAPI !== 'cli' || $forceErrorHandler) {
            if (!$errorHandler) {
                $errorHandler = new Handler($request);
            }
            $errorHandler->setup();
        }

        $this->router = $request->getRouter();
    }

    public static function create(array $options): self
    {
        $config = new Config($options);
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

    public function middleware(object|string $middleware): void
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
