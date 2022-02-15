<?php

declare(strict_types=1);

namespace Chuck;

interface TemplateInterface
{
    public function __construct(
        RequestInterface $request,
        array $defaults = [],
    );
    public function render(string $template, $context = []);
}
