<?php

declare(strict_types=1);

namespace Chuck\Util;

use \Closure;
use \InvalidArgumentException;
use \ValueError;
use \ReflectionFunction;
use \ReflectionMethod;
use \ReflectionObject;
use \ReflectionParameter;

use Chuck\RequestInterface;
use Chuck\ResponseInterface;


class Reflect
{
    public static function getReflectionFunction(
        object|string $callable,
        string $errorMsg
    ): ReflectionFunction|ReflectionMethod {
        if ($callable instanceof Closure) {
            return new ReflectionFunction($callable);
        } elseif (is_object($callable)) {
            return (new ReflectionObject($callable))->getMethod('__invoke');
        } elseif (is_callable($callable)) {
            return new ReflectionFunction($callable);
        } else {
            throw new InvalidArgumentException($errorMsg);
        }
    }


    public static function paramImplementsRequestInterface(ReflectionParameter $param): bool
    {
        $type = $param->getType();
        $requestType = (string)$type ?: false;

        if (!$requestType) return false;

        if (class_exists($requestType) || interface_exists($requestType)) {
            $requestTypeCls = new \ReflectionClass($requestType);
            if (
                $requestType === RequestInterface::class ||
                $requestTypeCls->implementsInterface(RequestInterface::class)
            ) {
                return true;
            }
        }

        return false;
    }

    public static function validateMiddleware(object|string $middleware): void
    {
        $rf = self::getReflectionFunction($middleware, "Middleware is not compatible");

        // Check the return type of the middleware
        try {
            $t = $rf->getReturnType();
            $returnType = (string)$t ?:
                throw new \InvalidArgumentException("Middleware return type must be given");
            $types = explode('|', $returnType);

            if (count($types) !== 2) {
                throw new ValueError("No union type ($returnType)");
            }

            /** @var class-string $type */
            foreach ($types as $type) {
                $returnTypeCls = new \ReflectionClass($type);

                if (!($returnTypeCls->implementsInterface(RequestInterface::class) ||
                    $returnTypeCls->implementsInterface(ResponseInterface::class)
                )) {
                    throw new ValueError("Wrong return type $returnType");
                }
            }
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException(
                $e->getMessage() . ": " .
                    "Middleware's return type must implement " . RequestInterface::class .
                    "|" . ResponseInterface::class
            );
        }

        // Check if two parameters are present
        $reflectionParams = $rf->getParameters();
        if (count($reflectionParams) !== 2) {
            throw new \InvalidArgumentException("Middleware must accept two parameters");
        }

        // Check $request parameter
        if (!self::paramImplementsRequestInterface($reflectionParams[0])) {
            throw new \InvalidArgumentException("Middleware's first parameter must implement " . RequestInterface::class);
        }

        // Check $next parameter
        $nextType = (string)$reflectionParams[1]->getType();

        if ($nextType !== 'callable') {
            throw new \InvalidArgumentException("Middleware's second parameter must be of type 'callable'");
        }
    }

    public static function getRequestParamOrError(
        RequestInterface $request,
        ReflectionParameter $param,
        string $name,
    ): RequestInterface {
        if (!self::paramImplementsRequestInterface($param)) {
            throw new ValueError("The type of the view paramter '$name' is not supported.");
        }

        return $request;
    }
}
