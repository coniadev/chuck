<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;

abstract class Renderer
{
    final public function __construct(
        protected Request $request,
        protected Registry $registry,
        protected array $args,
        protected mixed $options = null,
    ) {
    }

    abstract public function render(mixed $data): string;

    abstract public function response(mixed $data): Response;
}
