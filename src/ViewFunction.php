<?php

declare(strict_types=1);

namespace Chuck;

class ViewFunction extends View
{
    protected string|\Closure $callable;
    protected string $action;

    public function respond(): ResponseInterface
    {
        return 'tet';
    }
}
