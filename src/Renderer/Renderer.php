<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Body\Body;
use Chuck\RequestInterface;

abstract class Renderer implements RendererInterface
{
    public function __construct(
        protected RequestInterface $request,
        protected mixed $data,
        protected array $args,
    ) {
    }

    abstract public function render(): string;
    abstract public function body(): Body;
    abstract public function headers(): iterable;
}
