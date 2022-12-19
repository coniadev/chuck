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
use TypeError;
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

    public static function paramImplementsRequestInterface(ReflectionParameter $param): bool
    {
        $type = $param->getType();
        $requestType = (string)$type ?: false;

        if (!$requestType) {
            return false;
        }

        if (class_exists($requestType) || interface_exists($requestType)) {
            $requestTypeCls = new ReflectionClass($requestType);
            if (
                $requestType === RequestInterface::class ||
                $requestTypeCls->implementsInterface(RequestInterface::class)
            ) {
                return true;
            }
        }

        return false;
    }

    public static function validateMiddleware(callable $middleware): void
    {
        $rf = self::getReflectionFunction($middleware);

        // Check the return type of the middleware
        try {
            $t = $rf->getReturnType();
            $returnType = (string)$t ?:
                throw new TypeError("Middleware return type must be given");
            $types = explode('|', $returnType);

            if (count($types) !== 2) {
                throw new ArgumentCountError("No union type ($returnType)");
            }

            /** @var class-string $type */
            foreach ($types as $type) {
                $returnTypeCls = new ReflectionClass($type);

                if (
                    !(
                        $returnTypeCls->implementsInterface(RequestInterface::class) ||
                    $returnTypeCls->implementsInterface(ResponseInterface::class)
                    )
                ) {
                    throw new TypeError("Wrong return type $returnType");
                }
            }
        } catch (Throwable $e) {
            throw new TypeError(
                $e->getMessage() . ": " .
                    "Middleware's return type must implement " . RequestInterface::class .
                    "|" . ResponseInterface::class
            );
        }

        // Check if two parameters are present
        $rp = $rf->getParameters();
        if (count($rp) !== 2) {
            throw new ArgumentCountError("Middleware must accept two parameters");
        }

        // Check $request parameter
        if (!self::paramImplementsRequestInterface($rp[0])) {
            throw new TypeError("Middleware's first parameter must implement " . RequestInterface::class);
        }

        // Check $next parameter
        $nextType = (string)$rp[1]->getType();

        if ($nextType !== 'callable') {
            throw new TypeError("Middleware's second parameter must be of type 'callable'");
        }
    }
}
