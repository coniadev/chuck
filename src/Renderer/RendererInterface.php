<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Response\ResponseInterface;


interface RendererInterface
{
    public function render(): String;
    public function response(): ResponseInterface;
}
