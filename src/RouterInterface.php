<?php

declare(strict_types=1);

namespace Chuck;

interface RouterInterface
{
    public function getRoutes(): array;
    public function addRoute(RouteInterface $route);
    public function addStatic(
        string $name,
        string $prefix,
        string $dir,
    );
    public function routeUrl(string $name, array $args): string;
    public function routeName(): ?string;
    public function staticUrl(string $name, string $file, bool $bust = false, string $host = null): string;
    public function match(RequestInterface $request): ?Route;
    public function dispatch(RequestInterface $app);
    public function middleware(callable $middleware): void;
}
