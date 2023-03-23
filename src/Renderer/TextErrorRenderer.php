<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Error\Error;
use Conia\Chuck\Factory;
use Conia\Chuck\Response;

/** @psalm-api */
class TextErrorRenderer implements Renderer
{
    public function __construct(protected Factory $factory)
    {
    }

    public function render(mixed $data, mixed ...$args): string
    {
        assert(is_array($data));
        assert(isset($data['error']));
        assert($data['error'] instanceof Error);
        $error = $data['error'];

        return "Error: {$error->error}";
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        return Response::fromFactory($this->factory)->text($this->render($data));
    }
}
