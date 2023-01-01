<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Closure;
use Conia\Chuck\Renderer;

interface RouteInterface
{
    public function url(mixed ...$args): string;
    /** @return Closure|list{string, string}|string */
    public function view(): Closure|array|string;
    public function name(): string;
    public function args(): array;
    /** @no-named-arguments */
    public function method(string ...$args): static;
    /** @return list<string> */
    public function methods(): array;
    /** @param list<\Conia\Chuck\MiddlewareInterface> $middlewares */
    public function replaceMiddleware(array $middlewares): static;
    public function middleware(callable ...$middlewares): static;
    /** @return list<\Conia\Chuck\MiddlewareInterface> */
    public function middlewares(): array;
    public function render(string $renderer, mixed ...$args): static;
    public function controller(string $controller): void;
    public function getRenderer(): ?Renderer\Config;
    public function prefix(string $pattern, string $name): static;
    public function match(string $url): ?Route;
}
