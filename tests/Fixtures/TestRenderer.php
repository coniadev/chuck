<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Renderer\Renderer;

class TestRenderer extends Renderer
{
    public function render(mixed $data): string
    {
        return print_r($data, return: true);
    }

    public function response(mixed $data): Response
    {
        return (new ResponseFactory($this->registry))->text($this->render($data));
    }
}
