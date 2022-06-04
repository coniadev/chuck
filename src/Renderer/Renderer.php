<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Body\Body;
use Chuck\RequestInterface;

abstract class Renderer implements RendererInterface
{
    protected mixed $settings;

    public function __construct(
        protected RequestInterface $request,
        protected mixed $data,
        array $args = [],
        mixed $settings = null,
    ) {
        $this->args = $args;
        $this->settings = $settings;
    }

    abstract public function render(): Body;
    abstract public function headers(): iterable;
}
