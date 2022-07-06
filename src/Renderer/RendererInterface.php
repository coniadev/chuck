<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Response\ResponseInterface;


interface RendererInterface
{
    public function render(mixed $data): String;
    public function response(mixed $data): ResponseInterface;
}
