<?php

declare(strict_types=1);

namespace Chuck\Routing;

use Chuck\RequestInterface;
use Chuck\Response\ResponseInterface;


interface RouterInterface
{
    public function getRoute(): RouteInterface;
    public function addRoute(RouteInterface $route): void;
    public function addGroup(GroupInterface $group): void;
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
    public function addMiddleware(callable ...$middlewares): void;
    public function middlewares(): array;
}
