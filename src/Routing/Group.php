<?php

declare(strict_types=1);

namespace Chuck\Routing;


class Group
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

    public static function new(
        string $namePrefix,
        string $patternPrefix,
        \Closure $createClosure,
    ): self {
        return new self($namePrefix, $patternPrefix, $createClosure);
    }

    public function middleware(string|object ...$middlewares): self
    {
        $this->middlewares = $middlewares;

        return $this;
    }

    public function controller(string $controller): self
    {
        $this->controller = $controller;

        return $this;
    }

    public function render(string $renderer): self
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
            $route->middleware(...array_merge($this->middlewares, $route->middlewares()));
        }

        $this->router->addRoute($route);
    }

    public function create(RouterInterface $router): void
    {
        $this->router = $router;
        ($this->createClosure)($this);
    }
}
