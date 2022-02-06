

<?php

declare(strict_types=1);

namespace Chuck;

class ViewFunction extends View
{
    protected callable $callable;
    protected string $action;

    public function call(): mixed
    {
        return 'tet';
    }
}
