<?php

declare(strict_types=1);

namespace Chuck;

use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Chuck\Renderer\RendererInterface;


interface RegistryInterface extends ContainerInterface
{
    /**
     * @param string|class-string $id
     * @param object|class-string $entry
     */
    public function add(string $id, string|object $entry): void;
    public function new(string $id, mixed ...$args): object;
    public function instance(string $id): object;
    public function renderer(string $id, mixed ...$args): RendererInterface;
    public function logger(LoggerInterface $logger): void;
}
