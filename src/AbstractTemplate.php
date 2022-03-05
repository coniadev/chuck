<?php

declare(strict_types=1);

namespace Chuck;

abstract class AbstractTemplate
{
    abstract public function __construct(
        array $dirs,
        array $defaults = [],
    );
    abstract public function render(string $template, array $context = []): string;
    abstract public function exists(string $template): bool;
}
