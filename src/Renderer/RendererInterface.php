<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Response\Response;

interface RendererInterface
{
    public function render(mixed $data): string;
    public function response(mixed $data): Response;
}
