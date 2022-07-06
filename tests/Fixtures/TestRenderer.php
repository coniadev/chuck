<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Response\Response;
use Conia\Chuck\Renderer\Renderer;


class TestRenderer extends Renderer
{
    public function render(mixed $data): string
    {
        return (string)$data;
    }

    public function response(mixed $data): Response
    {
        return new Response($this->render($data));
    }
}
