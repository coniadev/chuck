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

    public function addRoute(array $params): void
    {
        $this->router->add($params);
    }

    public function addStaticRoute(
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
