<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

class Group implements GroupInterface
{
    use AddsRoutes;
    use AddsMiddleware;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected Router $router;

    protected string $namePrefix;
    protected ?string $renderer = null;
    protected ?string $controller = null;


    public function __construct(
        protected string $patternPrefix,
        protected \Closure $createClosure,
        ?string $namePrefix = null,
    ) {
        if ($namePrefix) {
            $this->namePrefix = $namePrefix;
        } else {
            $this->namePrefix = $this->patternPrefix;
        }
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

    public function addRoute(RouteInterface $route): void
    {
        $route->prefix($this->patternPrefix, $this->namePrefix);

        if ($this->renderer && empty($route->getRenderer())) {
            $route->render($this->renderer);
        }

        if ($this->controller) {
            $route->controller($this->controller);
        }

        if (!empty($this->middlewares)) {
            $route->replaceMiddleware(array_merge($this->middlewares, $route->middlewares()));
        }

        $this->router->addRoute($route);
    }

    public function create(Router $router): void
    {
        $this->router = $router;
        ($this->createClosure)($this);
    }
}
