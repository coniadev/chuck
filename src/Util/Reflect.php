<?php

declare(strict_types=1);

namespace Conia\Chuck\Util;

use ArgumentCountError;
use Closure;
use ReflectionClass;
use ReflectionFunction;
use ReflectionMethod;
use ReflectionObject;
use ReflectionParameter;
use Throwable;
use Conia\Chuck\Error\TypeError;
use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;

class Reflect
{
    public static function getReflectionFunction(
        callable $callable
    ): ReflectionFunction|ReflectionMethod {
        if ($callable instanceof Closure) {
            return new ReflectionFunction($callable);
        } elseif (is_object($callable)) {
            return (new ReflectionObject($callable))->getMethod('__invoke');
        } else {
            /** @var Closure|non-falsy-string $callable */
            return new ReflectionFunction($callable);
        }
    }
}
