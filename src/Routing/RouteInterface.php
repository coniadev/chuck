<?php

declare(strict_types=1);

namespace Chuck\Routing;

use \Closure;
use Chuck\Renderer;


interface RouteInterface
{
    public function url(array $args): string;
    public function view(): Closure|array|string;
    public function name(): string;
    public function args(): array;
    public function method(string ...$args): self;
    public function methods(): array;
    public function replaceMiddleware(callable|string ...$middlewares): self;
    public function middleware(callable|string ...$middlewares): self;
    public function middlewares(): array;
    public function render(string $renderer, mixed ...$args): self;
    public function controller(string $controller): void;
    public function getRenderer(): ?Renderer\Config;
    public function prefix(string $name, string $pattern): self;
    public function match(string $url): ?Route;
}
