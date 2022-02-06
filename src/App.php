<?php

declare(strict_types=1);

namespace Chuck;

use Monolog\Handler\HandlerInterface;

class App
{
    protected string $namespace;
    protected ConfigInterface $config;
    protected RequestInterface $request;
    protected RouterInterface $router;
    protected $localeNegotiatorClosure;

    public function __construct(ConfigInterface $config)
    {
        $this->config = $config;
        $this->initApp();
    }

    protected function initApp(): void
    {
        $this->loadSettings();

        $class = $this->config->di('Router');
        $this->router = new $class();

        $class = $this->config->di('Request');
        $this->request = new $class($this->config, $this->router);

        // Model needs to be initialized before the session
        // starts as we might have db sessions
        $model = $this->config->di('Model');
        $model::init($this->request);

        // Initialize logger
        $log = $this->config->di('Log');
        $log::init($this->request);

        $this->request->session->start();
        $this->loadErrorHandling();
    }

    protected function loadSettings(): void
    {
        session_set_cookie_params(['SameSite' => 'Strict']);
    }

    protected function loadErrorHandling(): void
    {
        $class = $this->config->di('Error');
        $error = new $class($this->request);
        $error->register();
    }

    public function route(
        string $name,
        string $route,
        string|callable $view,
        array $params = [],
    ): void {
        $this->router->add($name, $route, $view, $params);
    }

    protected function addMethodSpecificRoute(
        string $name,
        string $route,
        string|callable $view,
        string $method,
        array $params = [],
    ): void {
        if (array_key_exists('method', $params)) {
            throw new \InvalidArgumentException('Not allowed to define method');
        }

        $this->router->add(
            $name,
            $route,
            $view,
            array_merge($params, ['method' => $method])
        );
    }

    public function get(string $name, string $route, string|callable $view, array $params = [],): void
    {
        $this->addMethodSpecificRoute($name, $route, $view, 'GET', $params);
    }

    public function post(string $name, string $route, string|callable $view, array $params = [],): void
    {
        $this->addMethodSpecificRoute($name, $route, $view, 'POST', $params);
    }

    public function put(string $name, string $route, string|callable $view, array $params = [],): void
    {
        $this->addMethodSpecificRoute($name, $route, $view, 'PUT', $params);
    }

    public function delete(string $name, string $route, string|callable $view, array $params = [],): void
    {
        $this->addMethodSpecificRoute($name, $route, $view, 'DELETE', $params);
    }

    public function patch(string $name, string $route, string|callable $view, array $params = [],): void
    {
        $this->addMethodSpecificRoute($name, $route, $view, 'PATH', $params);
    }

    public function options(string $name, string $route, string|callable $view, array $params = [],): void
    {
        $this->addMethodSpecificRoute($name, $route, $view, 'OPTIONS', $params);
    }

    public function staticRoute(
        string $name,
        string $prefix,
        bool $cacheBusting = false
    ) {
        $this->router->addStatic($name, $prefix, $cacheBusting);
    }

    public function addRequestMethod(string $name, \Closure $func): void
    {
        $this->request->addRequestMethod($name, $func);
    }

    public function addLocaleNegotiator(\Closure $func): void
    {
        $this->localeNegotiatorClosure = $func;
    }

    public function negotiateLocale($request): void
    {

        if ($this->localeNegotiatorClosure) {
            $func = $this->localeNegotiatorClosure;
            $func($request);
        } else {
            setlocale(LC_ALL, 'C');
        }
    }

    public function pushLogHandler(HandlerInterface $handler): void
    {
        $log = $this->config->di('Log');
        $log::pushHandler($handler);
    }

    public function devel(): bool
    {
        return $this->config->get('devel');
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }

    public function dispatch(RequestInterface $request = null): ResponseInterface
    {
        // Should only be set in a test enviroment
        if ($request !== null) {
            $this->request = $request;
        }

        return $this->router->dispatch($this);
    }

    public function run(): void
    {
        $response = $this->dispatch();
        $response->respond();
    }
}
