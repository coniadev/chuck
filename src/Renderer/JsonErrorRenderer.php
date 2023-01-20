<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Error\Error;
use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;

class JsonErrorRenderer implements Renderer
{
    public function __construct(protected ResponseFactory $response)
    {
    }

    public function render(mixed $data, mixed ...$args): string
    {
        assert($data instanceof Error);

        $json = ['error' => $data->error];

        if ($data->debug) {
            $json['description'] = $data->description;
            $json['traceback'] = $data->traceback;
        }

        return json_encode($json, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        $response = $this->response->create();
        $response->header('Content-Type', 'application/json');
        $response->body($this->render($data, ...$args));

        return $response;
    }
}