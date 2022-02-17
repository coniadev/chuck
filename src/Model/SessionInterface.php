<?php

declare(strict_types=1);

namespace Core\Model;

interface SessionInterface
{
    public function open(string $savepath, string $id): bool;
    public function read(string $id): string;
    public function write(string $id, string $data): bool;
    public function destroy(string $id): bool;
    public function close(): bool;
    public function gc(int $max): bool;
}
