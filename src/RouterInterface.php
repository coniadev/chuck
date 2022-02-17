<?php

declare(strict_types=1);

namespace Chuck;

use \Closure;

interface RouterInterface
{
    public function getRoutes(): array;
    public function addRoute(RouteInterface $route): void;
    public function addStatic(
        string $name,
        string $prefix,
        string $dir,
    ): void;
    public function routeUrl(string $name, array $args): string;
    public function routeName(): ?string;
    public function staticUrl(
        string $name,
        string $path,
        bool $bust = false,
        string $host = null
    ): string;
    public function match(RequestInterface $request): ?Route;
    public function dispatch(RequestInterface $request): ResponseInterface;
    public function middleware(Closure|object|string $middleware): void;
    public function middlewares(): array;
}
