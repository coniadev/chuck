<?php

declare(strict_types=1);

namespace Chuck;


class Handler
{
    public function __construct(
        protected RequestInterface $request,
        protected RouteInterface $route,
        protected string|\Closure $view,
    ) {
    }

    public function respond(RequestInterface $request): ResponseInterface
    {
        $view = $this->view;

        if (is_callable($view)) {
            return $view($request);
        } else {
            if (is_string($view) && !str_contains($view, '::')) {
                $view .= '::__invoke';
            }

            [$ctrlName, $method] = explode('::', $view);

            if (class_exists($ctrlName)) {
                $ctrl = new $ctrlName($this->request);

                if (method_exists($ctrl, 'method')) {
                    return $ctrl->$method($request);
                } else {
                    throw new HttpInternalError(
                        $this->request,
                        "Controller method not found $view"
                    );
                }
            } else {
                throw new HttpInternalError(
                    $this->request,
                    "Controller not found ${ctrlName}"
                );
            }
        }
    }



    public function handle(callable $view): ResponseInterface
    {
        $handlers = $this->route->middlewares();
        $request = $this->request;

        while ($current = current($handlers)) {
            $next = next($handlers);

            if (false !== $next && $next == $current) {
                $request = $current($request, $next);
            }
        }

        return $this->respond();
    }
}
