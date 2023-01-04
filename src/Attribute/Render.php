<?php

declare(strict_types=1);

namespace Conia\Chuck\Attribute;

use Attribute;
use Conia\Chuck\ConfigInterface;
use Conia\Chuck\Request;
use Conia\Chuck\Response\ResponseInterface;

#[Attribute]
class Render
{
    protected array $args;

    public function __construct(protected string $renderer, mixed ...$args)
    {
        $this->args = $args;
    }

    public function response(Request $request, ConfigInterface $config, mixed $data): ResponseInterface
    {
        $renderer = $config->renderer(
            $request,
            $this->renderer,
            ...$this->args,
        );

        return $renderer->response($data);
    }
}
