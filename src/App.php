<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Error\Handler;
use Chuck\Logger;
use Chuck\Routing\GroupInterface;
use Chuck\Routing\RouteInterface;
use Chuck\Routing\RouterInterface;


class App
{
    protected RouterInterface $router;
    protected RegistryInterface $registry;
    protected ConfigInterface $config;

    public function __construct(protected RequestInterface $request)
    {
        $this->config = $request->getConfig();
        $this->router = $request->getRouter();
        $this->registry = $request->getRegistry();
    }

    public static function create(array|ConfigInterface $options): self
    {
        if ($options instanceof ConfigInterface) {
            $config = $options;
        } else {
            $config = new Config($options);
        }

        $registry = new Registry();
        $registry->logger(new Logger($config->get('loglevel'), $config->pathOrNull('logfile')));

        /** @var RouterInterface */
        $router = $registry->new(RouterInterface::class);

        /** @var RequestInterface */
        $request = $registry->new(RequestInterface::class, $config, $router, $registry);

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
        $this->router->middleware(...$middlewares);
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
