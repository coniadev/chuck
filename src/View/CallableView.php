<?php

declare(strict_types=1);

namespace Conia\Chuck\View;

use Closure;
use InvalidArgumentException;
use ReflectionFunction;
use Conia\Chuck\Registry;
use Conia\Chuck\RequestInterface;
use Conia\Chuck\Routing\RouteInterface;

class CallableView extends View
{
    /** @var Closure|callable-string */
    protected Closure|string $callable;

    public function __construct(
        protected RequestInterface $request,
        protected RouteInterface $route,
        protected Registry $registry,
        /** @var callable-array|callable-string|Closure */
        array|string|Closure $callable,
    ) {
        if (is_callable($callable)) {
            $this->callable = Closure::fromCallable($callable);
        } else {
            throw new InvalidArgumentException('Not a callable');
        }
    }

    public function execute(): mixed
    {
        return ($this->callable)(...$this->getViewArgs(
            $this->request,
            $this->callable,
            $this->route->args(),
        ));
    }

    /** @param $filter ?class-string */
    public function attributes(string $filter = null): array
    {
        return $this->getAttributes(new ReflectionFunction($this->callable), $filter);
    }
}
