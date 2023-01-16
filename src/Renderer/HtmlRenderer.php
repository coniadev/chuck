<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;

class HtmlRenderer implements Renderer
{
    public function __construct(protected ResponseFactory $response)
    {
    }

    public function render(mixed $data, mixed ...$args): string
    {
        return (string)$data;
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        return $this->response->html($this->render($data));
    }
}
