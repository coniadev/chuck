<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Error\Error;
use Conia\Chuck\Factory;
use Conia\Chuck\Response;

/** @psalm-api */
class HtmlErrorRenderer implements Renderer
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

        $title = htmlspecialchars($error->error);

        return sprintf(
            '<!doctype html>' .
            '<html lang="en">' .
            '<head>' .
            '<meta charset="utf-8">' .
            '<meta name="viewport" content="width=device-width, initial-scale=1">' .
            '<title>%s</title>' .
            '</head>' .
            '<body><h1>%s</h1></body></html>',
            $title,
            $title
        );
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        return Response::fromFactory($this->factory)->html($this->render($data));
    }
}
