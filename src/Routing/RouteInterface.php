<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Closure;
use Conia\Chuck\Renderer;

interface RouteInterface
{
    public function url(array $args): string;
    /** @property Closure|list{string, string}|string */
    public function view(): Closure|array|string;
    public function name(): string;
    public function args(): array;
    public function method(string ...$args): static;
    public function methods(): array;
    public function replaceMiddleware(callable|string ...$middlewares): static;
    public function middleware(callable|string ...$middlewares): static;
    public function middlewares(): array;
    public function render(string $renderer, mixed ...$args): static;
    public function controller(string $controller): void;
    public function getRenderer(): ?Renderer\Config;
    public function prefix(string $pattern, string $name): static;
    public function match(string $url): ?Route;
}
