<?php

declare(strict_types=1);

namespace Chuck\Tests\Fix;

use Chuck\Body\Body;
use Chuck\Body\Text;
use Chuck\Renderer\Renderer;


class TestRenderer extends Renderer
{
    public function render(): string
    {
        return '';
    }

    public function body(): Body
    {
        return new Text($this->render());
    }

    public function headers(): array
    {
        return [];
    }
}
