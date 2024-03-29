<?php

namespace SAML\HTTP;

use Exception;
use SAML\Configuration;
use SAML\Module\ControllerResolver;
use SAML\Session;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Controller\ArgumentResolver;
use Symfony\Component\HttpKernel\HttpKernel;
use Symfony\Component\Routing\RequestContext;

/**
 * Class that routes requests to responses.
 *
 * @package SimpleSAML
 */
class Router
{
    /** @var ArgumentResolver */
    protected $arguments;

    /** @var Configuration|null */
    protected $config = null;

    /** @var RequestContext */
    protected $context;

    /** @var EventDispatcher */
    protected $dispatcher;

    /** @var Request|null */
    protected $request = null;

    /** @var ControllerResolver */
    protected $resolver;

    /** @var Session|null */
    protected $session = null;

    /** @var RequestStack|null */
    protected $stack = null;


    /**
     * Router constructor.
     *
     * @param string $module
     */
    public function __construct($module)
    {
        $this->arguments = new ArgumentResolver();
        $this->context = new RequestContext();
        $this->resolver = new ControllerResolver($module);
        $this->dispatcher = new EventDispatcher();
    }


    /**
     * Process a given request.
     *
     * If no specific arguments are given, the default instances will be used (configuration, session, etc).
     *
     * @param Request|null $request
     *     The request to process. Defaults to the current one.
     *
     * @return Response A response suitable for the given request.
     *
     * @throws Exception If an error occurs.
     */
    public function process(Request $request = null)
    {
        if ($this->config === null) {
            $this->setConfiguration(Configuration::getInstance());
        }
        if ($this->session === null) {
            $this->setSession(Session::getSessionFromRequest());
        }

        if ($request === null) {
            $this->request = Request::createFromGlobals();
        } else {
            $this->request = $request;
        }

        $stack = new RequestStack();
        $stack->push($this->request);
        $this->context->fromRequest($this->request);
        $kernel = new HttpKernel($this->dispatcher, $this->resolver, $stack, $this->resolver);
        return $kernel->handle($this->request);
    }


    /**
     * Send a given response to the browser.
     *
     * @param Response $response The response to send.
     * @return void
     */
    public function send(Response $response)
    {
        if ($this->request === null) {
            throw new Exception("No request found to respond to");
        }
        $response->prepare($this->request);
        $response->send();
    }


    /**
     * Set the configuration to use by the controller.
     *
     * @param Configuration $config
     * @return void
     */
    public function setConfiguration(Configuration $config)
    {
        $this->config = $config;
        $this->resolver->setConfiguration($config);
    }


    /**
     * Set the session to use by the controller.
     *
     * @param Session $session
     * @return void
     */
    public function setSession(Session $session)
    {
        $this->session = $session;
        $this->resolver->setSession($session);
    }
}
