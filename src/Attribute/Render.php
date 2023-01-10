<?php

declare(strict_types=1);

namespace Conia\Chuck\Attribute;

use Attribute;
use Closure;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Renderer\Renderer;
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

    public function response(Request $request, Registry $registry, mixed $data): Response
    {
        $entry = $registry->tag(Renderer::class)->entry($this->renderer);
        $class = $entry->definition();
        $options = $entry->getArgs();

        if ($options instanceof Closure) {
            /** @var mixed */
            $options = $options();
        }

        assert(is_string($class));
        assert(is_subclass_of($class, Renderer::class));
        $renderer = new $class($request, $registry, $this->args, $options);

        return $renderer->response($data);
    }
}
