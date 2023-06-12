<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Error\Error;
use Conia\Chuck\Factory;
use Conia\Chuck\Response;

/** @psalm-api */
class JsonErrorRenderer implements Renderer
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
        $json = [
            'error' => $error->error,
            'description' => $error->description,
            'traceback' => $error->traceback,
            'code' => $error->code,
            'payload' => $error->payload,
        ];

        return json_encode($json, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        $response = Response::fromFactory($this->factory);
        $response->header('Content-Type', 'application/json');
        $response->body($this->render($data, ...$args));

        return $response;
    }
}
