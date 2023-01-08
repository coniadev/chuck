<?php

declare(strict_types=1);

namespace Conia\Chuck\Exception;

use Psr\Container\ContainerExceptionInterface;

class ContainerException extends RuntimeException implements ContainerExceptionInterface
{
}
