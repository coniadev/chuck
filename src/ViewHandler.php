<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\Routing\Route;
use Conia\Chuck\View;

class ViewHandler
{
    public function __construct(
        protected readonly View $view,
        protected readonly Registry $registry,
        protected readonly Route $route,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        return $this->view->respond(
            $request,
            $this->route,
            $this->registry,
        );
    }
}
