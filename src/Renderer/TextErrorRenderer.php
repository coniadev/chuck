<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Error\Error;
use Conia\Chuck\Psr\Factory;
use Conia\Chuck\Response;

class TextErrorRenderer implements Renderer
{
    public function __construct(protected Factory $factory)
    {
    }

    public function render(mixed $data, mixed ...$args): string
    {
        assert($data instanceof Error);

        $text = "Error: {$data->error}";

        if ($data->debug) {
            $text .= "\n\nDescription: {$data->description}\n\n";
            $text .= "-------------------------------------------------------\n\n";
            $text .= "Traceback:\n\n";
            $text .= $data->traceback;
        }

        return $text;
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        return Response::fromFactory($this->factory)->text($this->render($data));
    }
}
