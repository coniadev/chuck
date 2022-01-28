<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Exception\HttpNotFound;
use Chuck\Exception\HttpInternalError;
use Chuck\Exception\HttpBadRequest;

interface RouterInterface
{
    public function __construct(string $namespace);
    public function getRoutes(): array;
    public function add(array $route);
    public function addStatic(
        string $name,
        string $prefix,
        bool $cacheBusting = false
    );
    public function routeUrl(string $name, array $args): string;
    public function routeName(): ?string;
    public function staticUrl(string $name, string $path): string;
    public function match(RequestInterface $request): bool;
    public function dispatch(App $app);
}
