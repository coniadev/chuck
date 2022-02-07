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
        bool $cacheBusting = false
    );
    public function routeUrl(string $name, array $args): string;
    public function routeName(): ?string;
    public function staticUrl(string $name, string $path): string;
    public function match(RequestInterface $request): ?Route;
    public function dispatch(RequestInterface $app);
}
