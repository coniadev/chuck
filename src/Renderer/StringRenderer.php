<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\RequestInterface;
use Chuck\Util;

class StringRenderer implements RendererInterface
{
    public function __construct(
        RequestInterface $request,
        $data,
        string $identifier
    ) {
        $this->request = $request;
        $this->data = $data;
    }

    public function render(): string
    {
        return (string)$this->data;
    }

    public function headers(): iterable
    {
        return [];
    }
}
