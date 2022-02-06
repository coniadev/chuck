
<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Exception\HttpForbidden;
use Chuck\Exception\HttpUnauthorized;


class ViewController extends View
{
    protected Controller $ctrl;
    protected string $action;

    public function addCallable(Controller $ctrl, string $view): void
    {
        $this->ctrl = $ctrl;
        $this->view = $view;
    }

    public function call(): mixed
    {
        $request = $this->request;
        $session = $request->session;
        $ctrl = $this->ctrl;
        $view = $this->view;

        if ($ctrl->before($request)) {
            $response = $ctrl->$view($request);

            if ($response instanceof ResponseInterface) {
                return $ctrl->after($request, $response);
            } else {
                $renderer = $this->params['renderer'] ?? null;
                $class = $request->config->di('Response');

                return $ctrl->after(
                    $request,
                    new $class($request, $response, $renderer)
                );
            }
        } else {
            $auth = $request->config->di('Auth');
            if ($session->authenticatedUserId() || $auth::verifyJWT() || $auth::verifyApiKey()) {
                // User is authenticated but does not have the permissions
                throw new HttpForbidden($request);
            } else {
                if ($request->isXHR()) {
                    throw new HttpUnauthorized($request);
                } else {
                    // User needs to log in
                    $session->rememberReturnTo();
                    return $request->redirect($request->routeUrl('user:login'));
                }
            }
        }
    }
}
