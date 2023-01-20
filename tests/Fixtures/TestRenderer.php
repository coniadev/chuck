<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Response;

class TestRenderer implements Renderer
{
    public function __construct(protected Response $response)
    {
    }

    public function render(mixed $data, mixed ...$args): string
    {
        return print_r($data, return: true);
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        return $this->response->text($this->render($data));
    }
}
