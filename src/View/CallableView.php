<?php

declare(strict_types=1);

namespace Conia\Chuck\View;

use Closure;
use ReflectionFunction;
use Conia\Chuck\Registry;
use Conia\Chuck\Routing\Route;

class CallableView extends View
{
    protected Closure $callable;

    public function __construct(
        protected Route $route,
        Registry $registry,
        callable $callable,
    ) {
        $this->registry = $registry;
        $this->callable = Closure::fromCallable($callable);
    }

    public function execute(): mixed
    {
        return ($this->callable)(...$this->getArgs(
            self::getReflectionFunction($this->callable),
            $this->route->args(),
        ));
    }

    /** @param $filter ?class-string */
    public function attributes(string $filter = null): array
    {
        return $this->getAttributes(new ReflectionFunction($this->callable), $filter);
    }
}
