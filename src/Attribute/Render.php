<?php

declare(strict_types=1);

namespace Conia\Chuck\Attribute;

use Attribute;
use Conia\Chuck\Config;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;

#[Attribute]
class Render
{
    protected array $args;

    public function __construct(protected string $renderer, mixed ...$args)
    {
        $this->args = $args;
    }

    public function response(Request $request, Config $config, Registry $registry, mixed $data): Response
    {
        $renderer = $config->renderer(
            $request,
            $registry,
            $this->renderer,
            ...$this->args,
        );

        return $renderer->response($data);
    }
}
