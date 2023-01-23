<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Attribute;
use Conia\Chuck\Registry;
use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\ResponseWrapper;

/** @psalm-api */
#[Attribute]
class Render
{
    protected array $args;

    public function __construct(protected string $renderer, mixed ...$args)
    {
        $this->args = $args;
    }

    public function response(Registry $registry, mixed $data): ResponseWrapper
    {
        $renderer = $registry->tag(Renderer::class)->get($this->renderer);
        assert($renderer instanceof Renderer);

        return $renderer->response($data, ...$this->args);
    }
}
