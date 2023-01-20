<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Psr\Factory;
use Conia\Chuck\Response;

class HtmlRenderer implements Renderer
{
    public function __construct(protected Factory $factory)
    {
    }

    public function render(mixed $data, mixed ...$args): string
    {
        return (string)$data;
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        return Response::fromFactory($this->factory)->html($this->render($data));
    }
}
