<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Util\Reflect;


class Group
{
    protected RouterInterface $router;
    protected ?string $renderer = null;
    protected ?string $controller = null;
    protected array $middlewars = [];

    public function __construct(
        protected string $namePrefix,
        protected string $urlPrefix,
        protected \Closure $createClosure,
    ) {
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


    public function add(RouteInterface $route)
    {
        $route->prefix($this->namePrefix, $this->urlPrefix);

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

    public function create(RouterInterface $router)
    {
        $this->router = $router;
        ($this->createClosure)($this);
    }
}
