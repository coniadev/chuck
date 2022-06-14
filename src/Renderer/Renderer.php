<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Response\ResponseInterface;
use Chuck\RequestInterface;

abstract class Renderer implements RendererInterface
{
    final public function __construct(
        protected RequestInterface $request,
        protected mixed $data,
        protected array $args,
        protected mixed $settings = null,
    ) {
    }

    abstract public function response(): ResponseInterface;
}
