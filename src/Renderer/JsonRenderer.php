<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Factory;
use Conia\Chuck\Response;
use Traversable;

/** @psalm-api */
class JsonRenderer implements Renderer
{
    public function __construct(protected Factory $factory)
    {
    }

    public function render(mixed $data, mixed ...$args): string
    {
        $flags = JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR;

        if (count($args) > 0) {
            /** @var mixed */
            $arg = $args[array_key_first($args)];

            if (is_int($arg)) {
                $flags = $arg;
            }
        }

        if ($data instanceof Traversable) {
            return json_encode(iterator_to_array($data), $flags);
        }

        return json_encode($data, $flags);
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        $response = Response::fromFactory($this->factory);
        $response->header('Content-Type', 'application/json');
        $response->body($this->render($data, ...$args));

        return $response;
    }
}
