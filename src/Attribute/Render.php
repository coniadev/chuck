<?php

declare(strict_types=1);

namespace Conia\Chuck\Attribute;

use Attribute;
use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;

#[Attribute]
class Render
{
    protected array $args;

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
