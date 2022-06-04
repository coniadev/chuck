<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Body\Body;


interface RendererInterface
{
    public function render(): Body;
    public function headers(): iterable;
}
