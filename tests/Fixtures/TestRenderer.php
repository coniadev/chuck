<?php

declare(strict_types=1);

namespace Chuck\Tests\Fixtures;

use Chuck\Body\Text;
use Chuck\Renderer\Renderer;


class TestRenderer extends Renderer
{
    public function render(): Text
    {
        return new Text('');
    }

    public function headers(): array
    {
        return [];
    }
}
