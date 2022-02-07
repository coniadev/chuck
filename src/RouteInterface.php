<?php

declare(strict_types=1);

namespace Chuck;

interface RouteInterface
{
    public function getUrl(array $args): string;
    public function view(): string|callable;
    public function addArgs(array $args): void;
    public function method(string ...$args): self;
    public function permission(string ...$args): self;
}
