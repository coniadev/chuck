<?php

declare(strict_types=1);

namespace Chuck\Template;

abstract class TemplateEngine
{
    abstract public function __construct(
        array $dirs,
        array $defaults = [],
    );
    abstract public function render(string $moniker, array $context = []): string;
    abstract public function exists(string $moniker): bool;
}
