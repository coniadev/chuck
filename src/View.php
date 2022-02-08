<?php

declare(strict_types=1);

namespace Chuck;


abstract class View
{
    public function __construct(
        protected RequestInterface $request,
        protected RouteInterface $route,
        protected RouterInterface $router,
        protected string|\Closure $view,
    ) {
        $this->init();
    }

    abstract protected function init(): void;
    abstract public function respond(): ResponseInterface;

    protected function handle(callable $view): ResponseInterface
    {
        $middlewares = $this->route->middlewares();

        return [];
    }
}
