<?php
namespace Extension14v\T3lockdown\Middleware;

use Extension14v\T3lockdown\Exception\RequestNotAllowedException;
use Extension14v\T3lockdown\Service\LockdownService;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Log\LogManager;

readonly class Lockdown implements MiddlewareInterface
{
    private LoggerInterface $logger;

    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly LockdownService          $lockdownService,
        LogManager $logManager
    ) {
        $this->logger = $logManager->getLogger(__CLASS__);
    }

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        try {
            $this->lockdownService->handle($request);
        } catch (RequestNotAllowedException $e) {
            $this->logger->warning('Blocked suspicious request', [
                'message' => $e->getMessage(),
                'uri' => (string)$request->getUri(),
                'method' => $request->getMethod(),
                'ip' => $request->getServerParams()['REMOTE_ADDR'] ?? null,
            ]);
            $response = $this->responseFactory->createResponse(403);
            $response->getBody()->write($this->buildForbiddenHtml($e->getMessage()));
            return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
        } catch (\Throwable $exception) {
            $this->logger->error('Lockdown middleware failed', [
                'exception' => $exception,
                'uri' => (string)$request->getUri(),
            ]);
            throw new \RuntimeException(
                'Lockdown middleware failed: ' . $exception::class . ' - ' . $exception->getMessage(),
                0,
                $exception
            );
        }
        return $handler->handle($request);
    }

    private function buildForbiddenHtml(string $message): string
    {
        $safeMessage = htmlspecialchars($message, ENT_QUOTES | ENT_HTML5);
        return <<<HTML
            <!DOCTYPE html>
            <html lang="de">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>403 - Access denied</title>
                <style>
                    body {
                        margin: 0;
                        padding: 2rem;
                        font-family: Arial, sans-serif;
                        background: #f5f5f5;
                        color: #222;
                    }
            
                    .wrapper {
                        max-width: 720px;
                        margin: 4rem auto;
                        background: #fff;
                        border: 1px solid #ddd;
                        border-radius: 8px;
                        padding: 2rem;
                        box-shadow: 0 4px 18px rgba(0, 0, 0, 0.08);
                    }
            
                    h1 {
                        margin-top: 0;
                        color: #b42318;
                        font-size: 2rem;
                    }
            
                    p {
                        line-height: 1.6;
                        margin-bottom: 1rem;
                    }
                </style>
            </head>
            <body>
                <main class="wrapper">
                    <h1>403 – Access denied</h1>
                    <p>Your request was blocked for security reasons.</p>
                </main>
            </body>
            </html>
            HTML;
    }
}