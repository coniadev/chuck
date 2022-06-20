<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Response\ResponseInterface;
use Chuck\RequestInterface;

abstract class Renderer implements RendererInterface
{
    final public function __construct(
        protected RequestInterface $request,
        protected array $args,
        protected mixed $options = null,
    ) {
    }

    abstract public function render(mixed $data): string;
    abstract public function response(mixed $data): ResponseInterface;
}
