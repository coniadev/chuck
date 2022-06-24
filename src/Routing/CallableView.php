<?php

declare(strict_types=1);

namespace Chuck\Routing;

use \Closure;
use Chuck\RequestInterface;
use Chuck\Routing\RouteInterface;


class CallableView extends View
{
    public function __construct(
        protected RequestInterface $request,
        protected RouteInterface $route,
        /** @var callable-array|callable-string|Closure */
        protected array|string|Closure $callable,
    ) {
    }

    public function execute(): mixed
    {
        return ($this->callable)(...$this->getViewArgs(
            $this->request,
            $this->callable,
            $this->route->args(),
        ));
    }

    // public function attributes(): array
    // {
    // return [];
    // }
}
