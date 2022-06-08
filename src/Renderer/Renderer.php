<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Body\Body;
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

    abstract public function render(): Body;
    abstract public function headers(): iterable;
}
