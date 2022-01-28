<?php

declare(strict_types=1);

namespace Chuck;

interface ConfigInterface
{
    public function __construct(string $configFile, array $custom = []);
    public function get(string $key);
    public function getOr(string $key, $default);
    public function path(string $key);
    public function di(string $key);
    public function getMailer();
}
