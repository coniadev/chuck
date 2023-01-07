<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Request;
use Conia\Chuck\Response;

class Dispatcher
{
    public readonly array $queue;

    public function __construct(array $queue)
    {
        $this->queue = $queue;
    }

    protected function handle(array $queue, Request $request): Response
    {
        $handler = $queue[0];

        if ($handler instanceof MiddlewareInterface) {
            return $handler(
                $request,
                function (
                    Request $req
                ) use ($queue): Response {
                    return $this->handle(
                        array_slice($queue, 1),
                        $req,
                    );
                }
            );
        }

        return $handler($request);
    }

    /**
     * Recursively calls the callables in the middleware/view handler queue
     * and then the view callable.
     *
     * @psalm-param list<MiddlewareInterface> $handlerStack
     * @psalm-param Closure(Request):Response $viewClosure
     */
    public function dispatch(
        Request $request,
    ): Response {
        return $this->handle($this->queue, $request);
    }
}
