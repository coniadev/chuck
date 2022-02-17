<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\RequestInterface;

interface RendererInterface
{
    public function __construct(
        RequestInterface $request,
        mixed $data,
        array $args,
    );
    public function render(): string;
    public function headers(): iterable;
}
