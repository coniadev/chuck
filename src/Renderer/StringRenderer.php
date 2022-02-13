<?php

declare(strict_types=1);

namespace Chuck\Renderer;


class StringRenderer extends Renderer
{
    public function render(): string
    {
        return (string)$this->data;
    }

    public function headers(): iterable
    {
        return [];
    }
}
