<?php

declare(strict_types=1);

namespace Chuck\Error;

use Psr\Container\NotFoundExceptionInterface;


class RegistryEntryNotFoundError extends \Exception implements NotFoundExceptionInterface
{
}
