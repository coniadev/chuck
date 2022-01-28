<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Exception\HttpBadRequest;

abstract class Controller
{
    protected $params = [];

    public function __construct($params)
    {
        $this->params = $params;
    }

    protected function isAuthorized(string $requirement, array $permissions): bool
    {
        if (in_array($requirement, $permissions)) {
            return true;
        }

        return false;
    }

    protected function shouldVerify(RequestInterface $request): bool
    {
        $method = $request->method();

        return
            $request->isXHR() ||
            $method === 'post' ||
            $method === 'put' ||
            $method === 'delete';
    }

    protected function verifyCsrf(RequestInterface $request): bool
    {
        if (!$this->params['csrf']) {
            return true;
        }

        if ($this->shouldVerify($request)) {
            if ($request->session->csrf->verify($this->params['csrf_page'])) {
                return true;
            }
            return false;
        }
        return true;
    }

    public function before(RequestInterface $request): bool
    {
        if (!$this->verifyCsrf($request)) {
            throw new HttpBadRequest($request, 'CSRF Error');
        }

        $requiredPermissions = $this->params['permission'] ?? null;

        if (!$requiredPermissions) {
            return true;
        }

        $permissions = $request->permissions();

        if (gettype($requiredPermissions) === 'string') {
            return $this->isAuthorized($requiredPermissions, $permissions);
        } else {
            foreach ($requiredPermissions as $required) {
                return $this->isAuthorized($required, $permissions);
            }
        }

        return false;
    }

    public function after(
        RequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        return $response;
    }
}
