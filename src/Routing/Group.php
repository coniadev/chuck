<?php

declare(strict_types=1);

namespace Chuck\Routing;


class Group implements GroupInterface
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected RouterInterface $router;

    protected ?string $renderer = null;
    protected ?string $controller = null;
    protected array $middlewares = [];


    public function __construct(
        protected string $namePrefix,
        protected string $patternPrefix,
        protected \Closure $createClosure,
    ) {
    }

    public function middleware(string|object ...$middlewares): static
    {
        foreach ($middlewares as $middleware) {
            $this->middlewares[] = $middleware;
        }

        return $this;
    }

    public function controller(string $controller): static
    {
        $this->controller = $controller;

        return $this;
    }

    public function render(string $renderer): static
    {
        $this->renderer = $renderer;

        return $this;
    }

    public function add(RouteInterface $route): void
    {
        $route->prefix($this->namePrefix, $this->patternPrefix);

        if ($this->renderer && empty($route->getRenderer())) {
            $route->render($this->renderer);
        }

        if ($this->controller) {
            $route->controller($this->controller);
        }

        if (!empty($this->middlewares)) {
            $route->replaceMiddleware(...array_merge($this->middlewares, $route->middlewares()));
        }

        $this->router->addRoute($route);
    }

    public function create(RouterInterface $router): void
    {
        $this->router = $router;
        ($this->createClosure)($this);
    }
}
