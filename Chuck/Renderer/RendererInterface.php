<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\RequestInterface;

interface RendererInterface
{
    public function __construct(
        RequestInterface $request,
        $data,
        string $identifier
    );
    public function render(): string;
    public function headers(): iterable;
}
