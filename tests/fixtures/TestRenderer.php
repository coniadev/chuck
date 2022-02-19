<?php

declare(strict_types=1);

namespace Chuck\Tests\Fix;

use Chuck\Renderer\Renderer;


class TestRenderer extends Renderer
{
    public function render(): string
    {
        return '';
    }

    public function headers(): array
    {
        return [];
    }
}
