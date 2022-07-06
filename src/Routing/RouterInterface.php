<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;


interface RouterInterface
{
    public function getRoute(): RouteInterface;
    public function addRoute(RouteInterface $route): void;
    public function addGroup(GroupInterface $group): void;
    public function addStatic(
        string $prefix,
        string $dir,
        ?string $name = null,
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
