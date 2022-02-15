<?php

declare(strict_types=1);

namespace Chuck;

use Monolog\Handler\HandlerInterface;


class App
{
    protected string $namespace;
    protected RouterInterface $router;
    protected ConfigInterface $config;
    protected $localeNegotiatorClosure;

    public function __construct(protected RequestInterface $request)
    {
        // Initialize logger
        // $log = $this->config->di('Log');
        // $log::init($request);

        $request->session->start();
        $this->router = $request->router();
        $this->config = $request->config;

        // $error = new Error($request);
        // $error->register();
    }

    public static function create(array $settings): self
    {
        session_set_cookie_params(['SameSite' => 'Strict']);

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
        return $this->request->router();
    }

    public function config(): ConfigInterface
    {
        return $this->request->config;
    }

    public function route(RouteInterface $route): void
    {
        $this->router->addRoute($route);
    }

    public function staticRoute(
        string $name,
        string $prefix,
        string $path,
    ) {
        $this->router->addStatic($name, $prefix, $path);
    }

    public function middleware(callable $middleware): void
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

    public function pushLogHandler(HandlerInterface $handler): void
    {
        // $log = $this->config->di('Log');
        // $log::pushHandler($handler);
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
