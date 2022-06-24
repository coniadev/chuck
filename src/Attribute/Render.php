<?php

declare(strict_types=1);

namespace Chuck\Attribute;

use \Attribute;
use \Chuck\RequestInterface;
use \Chuck\Response\ResponseInterface;


#[Attribute]
class Render
{
    protected mixed $args;

    public function __construct(protected string $renderer, mixed ...$args)
    {
        $this->args = $args;
    }

    public function response(RequestInterface $request, mixed $data): ResponseInterface
    {
        $renderer = $request->config()->renderer(
            $request,
            $this->renderer,
            ...$this->args,
        );

        return $renderer->response($data);
    }
}
