<?php

declare(strict_types=1);

namespace Conia\Chuck\View;

use Conia\Chuck\Registry;
use Conia\Chuck\Response;
use Conia\Chuck\Routing\Route;

class ViewHandler
{
    public function __construct(
        protected readonly View $view,
        protected readonly Registry $registry,
        protected readonly Route $route,
    ) {
    }

    public function __invoke(): Response
    {
        return $this->view->respond(
            $this->route,
            $this->registry,
        );
    }
}
