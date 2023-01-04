<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Request;
use Conia\Chuck\Response\ResponseInterface;

abstract class Renderer implements RendererInterface
{
    final public function __construct(
        protected Request $request,
        protected array $args,
        protected mixed $options = null,
    ) {
    }

    abstract public function render(mixed $data): string;
    abstract public function response(mixed $data): ResponseInterface;
}
