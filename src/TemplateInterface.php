<?php

declare(strict_types=1);

namespace Chuck;

interface TemplateInterface
{
    public function __construct(
        RequestInterface $request,
        array $defaults = [],
        ?string $path = null
    );
    public function render(string $template, $context = []);
    public function exists(string $template): bool;
}
