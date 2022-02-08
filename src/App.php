<?php

declare(strict_types=1);

namespace Chuck;

use Monolog\Handler\HandlerInterface;


class App
{
    protected string $namespace;
    protected ?RouterInterface $router = null;
    protected $localeNegotiatorClosure;

    public function __construct(protected RequestInterface $request)
    {
        // Initialize logger
        // $log = $this->config->di('Log');
        // $log::init($request);

        $request->session->start();
        $this->router = $request->router();

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

    public function router(): RouterInterface
    {
        if (!$this->router) {
            $this->router = $this->request->router();
        }

        return $this->router;
    }

    public function route(RouteInterface $route): void
    {
        $this->router()->addRoute($route);
    }

    public function staticRoute(
        string $name,
        string $prefix,
        string $path,
    ) {
        $this->router()->addStatic($name, $prefix, $path);
    }

    public function setResponse(string $class): void
    {
        $this->router()->setResponse($class);
    }

    public function setRenderer(string $name, string $class): void
    {
        $this->router()->setRenderer($name, $class);
    }

    public function pushLogHandler(HandlerInterface $handler): void
    {
        // $log = $this->config->di('Log');
        // $log::pushHandler($handler);
    }

    public function run(): void
    {
        $response = $this->router->dispatch($this->request);
        $response->respond();
    }
}
