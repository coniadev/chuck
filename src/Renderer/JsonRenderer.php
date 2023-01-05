<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Util\Json;
use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;

class JsonRenderer extends Renderer
{
    public function render(mixed $data): string
    {
        return Json::encode($data);
    }

    public function response(mixed $data): Response
    {
        return (new ResponseFactory($this->registry))->json($data);
    }
}
