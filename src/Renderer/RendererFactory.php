<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\RequestInterface;
use Chuck\Renderer\Renderer;

class RendererFactory
{
    /** @var class-string */
    protected readonly string $class;
    protected readonly mixed $settings;

    public function __construct(
        protected array $renderers,
        protected string $name,
    ) {
        $this->class = $renderers[$name]['class'];
        $this->settings = $renderers[$name]['settings'];
    }

    public function create(RequestInterface $request, mixed $data, array $args): Renderer
    {
        return new ($this->class)($request, $data, $args, $this->settings);
    }
}
