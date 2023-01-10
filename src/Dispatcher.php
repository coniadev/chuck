<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\MiddlewareInterface as PsrMiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * @psalm-type HandlerList = list<MiddlewareInterface|PsrMiddlewareInterface|ViewHandler>
 */
class Dispatcher
{
    protected readonly StreamFactoryInterface $streamFactory;

    /**
     * @psalm-param HandlerList $queue
     */
    public function __construct(
        protected readonly array $queue,
        protected readonly Registry $registry
    ) {
        $sf = $registry->get(StreamFactoryInterface::class);
        assert($sf instanceof StreamFactoryInterface);
        $this->streamFactory = $sf;
    }

    /**
     * Recursively calls the callables in the middleware/view handler queue
     * and then the view callable.
     *
     * @psalm-param HandlerList $queue
     */
    public function handle(array $queue, Request $request): Response
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
        } elseif ($handler instanceof PsrMiddlewareInterface) {
            return new Response($handler->process(
                $request->psr7(),
                // Create an anonymous PSR-15 RequestHandler
                new class ($this, array_slice($queue, 1)) implements RequestHandlerInterface {
                    /** @psalm-param HandlerList $queue */
                    public function __construct(
                        protected readonly Dispatcher $dispatcher,
                        protected readonly array $queue
                    ) {
                    }

                    public function handle(ServerRequestInterface $request): ResponseInterface
                    {
                        return $this->dispatcher->handle($this->queue, new Request($request))->psr7();
                    }
                }
            ), $this->streamFactory);
        }

        return $handler($request);
    }

    public function dispatch(
        Request $request,
    ): Response {
        return $this->handle($this->queue, $request);
    }
}
