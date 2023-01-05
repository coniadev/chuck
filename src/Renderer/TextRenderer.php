<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;

class TextRenderer extends Renderer
{
    public function render(mixed $data): string
    {
        return (string)$data;
    }

    public function response(mixed $data): Response
    {
        return (new ResponseFactory($this->registry))->text($this->render($data));
    }
}
