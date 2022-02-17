<?php

declare(strict_types=1);

namespace Chuck;

interface SchemaInterface
{
    public function __construct(
        bool $list = false,
        bool $keepUnknown = false,
        array $langs = [],
        ?string $title = null,
    );
    public function validate(array $data, int $level = 1): bool;
    public function errors(bool $grouped = false): array;
    public function values(): array;
    public function pristineValues(): array;
}
