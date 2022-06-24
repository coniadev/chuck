<?php

declare(strict_types=1);

namespace Chuck\Routing;

use \Closure;
use \InvalidArgumentException;
use \ReflectionFunction;
use \ValueError;
use Chuck\RequestInterface;
use Chuck\Routing\RouteInterface;


class CallableView extends View
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected array $attributes;
    /** @var Closure|callable-string */
    protected Closure|string $callable;

    public function __construct(
        protected RequestInterface $request,
        protected RouteInterface $route,
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

    public function attributes(): array
    {
        /** @psalm-suppress RedundantPropertyInitializationCheck */
        if (!isset($this->attributes)) {
            $this->attributes = $this->getAttributes(new ReflectionFunction($this->callable));
        }

        return $this->attributes;
    }
}
