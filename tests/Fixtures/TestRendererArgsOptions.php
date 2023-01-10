<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;

class TestRendererArgsOptions extends Renderer
{
    public function render(mixed $data): string
    {
        return print_r($this->prepareData($data), return: true);
    }

    public function response(mixed $data): Response
    {
        $data = $this->prepareData($data);

        if (is_array($data)) {
            return (new ResponseFactory($this->registry))->json($data);
        }

        return (new ResponseFactory($this->registry))->text($this->render($data));
    }

    private function prepareData(mixed $data): mixed
    {
        if (is_array($data) && is_array($this->args)) {
            $data = array_merge($data, $this->args);
        }
        if (is_array($data) && is_array($this->options)) {
            $data = array_merge($data, $this->options);
        }

        return $data;
    }
}
