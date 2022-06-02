<?php

declare(strict_types=1);

namespace Chuck\Routing;

use Chuck\RequestInterface;
use Chuck\ResponseInterface;


interface RouterInterface
{
    public function getRoute(): RouteInterface;
    public function addRoute(RouteInterface $route): void;
    public function addStatic(
        string $name,
        string $prefix,
        string $dir,
    ): void;
    public function routeUrl(string $__routeName__, mixed ...$args): string;
    public function staticUrl(
        string $name,
        string $path,
        bool $bust = false,
        string $host = null
    ): string;
    public function match(RequestInterface $request): ?Route;
    public function dispatch(RequestInterface $request): ResponseInterface;
    public function middlewares(): array;
}
