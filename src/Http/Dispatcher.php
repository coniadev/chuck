<?php

declare(strict_types=1);

namespace Conia\Chuck\Http;

use Conia\Chuck\Factory;
use Conia\Chuck\Middleware;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Psr\Http\Message\ResponseInterface as PsrResponse;
use Psr\Http\Message\ServerRequestInterface as PsrServerRequest;
use Psr\Http\Server\MiddlewareInterface as PsrMiddleware;
use Psr\Http\Server\RequestHandlerInterface as PsrRequestHandler;

class Dispatcher
{
    protected Factory $factory;

    public function __construct(
        protected readonly array $queue,
        Registry $registry
    ) {
        $factory = $registry->get(Factory::class);
        assert($factory instanceof Factory);
        $this->factory = $factory;
    }

    /**
     * Recursively calls the callables in the middleware/view handler queue
     * and then the view callable.
     */
    public function handle(array $queue, Request $request): PsrResponse
    {
        /** @psalm-var non-empty-list<Middleware|PsrMiddleware|ViewHandler> $queue */
        $handler = $queue[0];

        if ($handler instanceof Middleware) {
            return $handler(
                $request,
                function (Request $req) use ($queue): Response {
                    return new Response($this->handle(array_slice($queue, 1), $req), $this->factory);
                }
            )->psr();
        } elseif ($handler instanceof PsrMiddleware) {
            return $handler->process(
                $request->psr(),
                // Create an anonymous PSR-15 RequestHandler
                new class ($this, array_slice($queue, 1)) implements PsrRequestHandler {
                    public function __construct(
                        protected readonly Dispatcher $dispatcher,
                        protected readonly array $queue
                    ) {
                    }

                    public function handle(PsrServerRequest $request): PsrResponse
                    {
                        return $this->dispatcher->handle($this->queue, new Request($request));
                    }
                }
            );
        }

        return $handler();
    }

    public function dispatch(
        Request $request,
    ): PsrResponse {
        return $this->handle($this->queue, $request);
    }
}
