<?php

declare(strict_types=1);

namespace Chuck;

interface ConfigInterface
{
    public function __construct(array $config);
    public function get(string $key);
    public function path(string $key);
}
