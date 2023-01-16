<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Error\Error;
use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;

class HtmlErrorRenderer implements Renderer
{
    public function __construct(protected ResponseFactory $response)
    {
    }

    public function render(mixed $data, mixed ...$args): string
    {
        assert($data instanceof Error);

        $error = htmlspecialchars($data->error);
        $body = "<h1>{$error}</h1>";

        if ($data->debug) {
            $description = htmlspecialchars($data->description);
            $body .= "<h2>{$description}</h2>";

            $traceback = str_replace(
                ['<', '>', '"'],
                ['&lt;', '&gt', '&quot;'],
                $data->traceback
            );
            $traceback = implode('<br>#', explode('#', $traceback));
            $body .= preg_replace('/^<br>/', '', $traceback);
        }

        return $body;
    }

    public function response(mixed $data, mixed ...$args): Response
    {
        return $this->response->html($this->render($data));
    }
}
