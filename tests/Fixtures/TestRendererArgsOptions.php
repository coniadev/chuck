<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;

class TestRendererArgsOptions implements Renderer
{
    public function __construct(
        protected ResponseFactory $response,
        protected int $option1,
        protected string $option2,
    ) {
    }

    public function render(mixed $data, mixed ...$args): string
    {
        return print_r($this->prepareData($data, $args), return: true);
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        $data = $this->prepareData($data, $args);

        if (is_array($data)) {
            return $this->response->json($data);
        }

        return $this->response->text($this->render($data));
    }

    private function prepareData(mixed $data, array $args): mixed
    {
        if (is_array($data)) {
            $data = array_merge($data, $args);
        }
        if (is_array($data)) {
            $data = array_merge($data, ['option1' => $this->option1, 'option2' => $this->option2]);
        }

        return $data;
    }
}
