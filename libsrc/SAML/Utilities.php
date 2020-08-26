<?php

namespace SAML;

use DOMElement;
use DOMNode;
use Exception;
use SAML\Auth\State;
use SAML\Error\Error;
use SAML\Utils\Arrays;
use SAML\Utils\Attributes;
use SAML\Utils\Auth;
use SAML\Utils\Config;
use SAML\Utils\Config\Metadata;
use SAML\Utils\Crypto;
use SAML\Utils\HTTP;
use SAML\Utils\Net;
use SAML\Utils\Random;
use SAML\Utils\System;
use SAML\Utils\Time;
use SAML\Utils\XML;
use SAML\XML\Validator;
use SAML2\Utils;

/**
 * Misc static functions that is used several places.in example parsing and id generation.
 *
 * @author Andreas Åkre Solberg, UNINETT AS. <andreas.solberg@uninett.no>
 * @package SimpleSAMLphp
 *
 * @deprecated This entire class will be removed in SimpleSAMLphp 2.0.
 */

class Utilities
{
    /**
     * @deprecated This property will be removed in SSP 2.0. Please use SimpleSAML\Logger::isErrorMasked() instead.
     * @var int
     */
    public static $logMask = 0;


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::getSelfHost() instead.
     * @return string
     */
    public static function getSelfHost()
    {
        return HTTP::getSelfHost();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::getSelfURLHost() instead.
     * @return string
     */
    public static function selfURLhost()
    {
        return HTTP::getSelfURLHost();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::isHTTPS() instead.
     * @return bool
     */
    public static function isHTTPS()
    {
        return HTTP::isHTTPS();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::getSelfURLNoQuery()
     *     instead.
     * @return string
     */
    public static function selfURLNoQuery()
    {
        return HTTP::getSelfURLNoQuery();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::getSelfHostWithPath()
     *     instead.
     * @return string
     */
    public static function getSelfHostWithPath()
    {
        return HTTP::getSelfHostWithPath();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::getFirstPathElement()
     *     instead.
     * @param bool $trailingslash
     * @return string
     */
    public static function getFirstPathElement($trailingslash = true)
    {
        return HTTP::getFirstPathElement($trailingslash);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::getSelfURL() instead.
     * @return string
     */
    public static function selfURL()
    {
        return HTTP::getSelfURL();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::getBaseURL() instead.
     * @return string
     */
    public static function getBaseURL()
    {
        return HTTP::getBaseURL();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::addURLParameters() instead.
     * @param string $url
     * @param array $parameters
     * @return string
     */
    public static function addURLparameter($url, $parameters)
    {
        return HTTP::addURLParameters($url, $parameters);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use \SimpleSAML\Utils\HTTP::checkURLAllowed() instead.
     * @param string $url
     * @param array|null $trustedSites
     * @return string
     */
    public static function checkURLAllowed($url, array $trustedSites = null)
    {
        return HTTP::checkURLAllowed($url, $trustedSites);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use \SimpleSAML\Auth\State::parseStateID() instead.
     * @param string $stateId
     * @return array
     */
    public static function parseStateID($stateId)
    {
        return State::parseStateID($stateId);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0.
     * @param string|null $start
     * @param string|null $end
     * @return bool
     */
    public static function checkDateConditions($start = null, $end = null)
    {
        $currentTime = time();

        if (!empty($start)) {
            $startTime = Utils::xsDateTimeToTimestamp($start);
            // Allow for a 10 minute difference in Time
            if (($startTime < 0) || (($startTime - 600) > $currentTime)) {
                return false;
            }
        }
        if (!empty($end)) {
            $endTime = Utils::xsDateTimeToTimestamp($end);
            if (($endTime < 0) || ($endTime <= $currentTime)) {
                return false;
            }
        }
        return true;
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Random::generateID() instead.
     * @return string
     */
    public static function generateID()
    {
        return Random::generateID();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use \SimpleSAML\Utils\Time::generateTimestamp()
     *     instead.
     * @param int|null $instant
     * @return string
     */
    public static function generateTimestamp($instant = null)
    {
        return Time::generateTimestamp($instant);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use \SimpleSAML\Utils\Time::parseDuration() instead.
     * @param string $duration
     * @param int|null $timestamp
     * @return int
     */
    public static function parseDuration($duration, $timestamp = null)
    {
        return Time::parseDuration($duration, $timestamp);
    }


    /**
     * @param string $trackId
     * @param int|null $errorCode
     * @param Exception|null $e
     * @return void
     *@throws Error
     * @deprecated This method will be removed in SSP 2.0. Please raise a SimpleSAML\Error\Error exception instead.
     */
    public static function fatalError($trackId = 'na', $errorCode = null, Exception $e = null)
    {
        throw new Error($errorCode, $e);
    }


    /**
     * @deprecated This method will be removed in version 2.0. Use SimpleSAML\Utils\Net::ipCIDRcheck() instead.
     * @param string $cidr
     * @param string|null $ip
     * @return bool
     */
    public static function ipCIDRcheck($cidr, $ip = null)
    {
        return Net::ipCIDRcheck($cidr, $ip);
    }


    /**
     * @param string $url
     * @param array $parameters
     * @return void
     */
    private static function doRedirect($url, $parameters = [])
    {
        assert(is_string($url));
        assert(!empty($url));
        assert(is_array($parameters));

        if (!empty($parameters)) {
            $url = self::addURLparameter($url, $parameters);
        }

        /* Set the HTTP result code. This is either 303 See Other or
         * 302 Found. HTTP 303 See Other is sent if the HTTP version
         * is HTTP/1.1 and the request type was a POST request.
         */
        if ($_SERVER['SERVER_PROTOCOL'] === 'HTTP/1.1' &&
            $_SERVER['REQUEST_METHOD'] === 'POST'
        ) {
            $code = 303;
        } else {
            $code = 302;
        }

        if (strlen($url) > 2048) {
            Logger::warning('Redirecting to a URL longer than 2048 bytes.');
        }

        // Set the location header
        header('Location: '.$url, true, $code);

        // Disable caching of this response
        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');

        // Show a minimal web page with a clickable link to the URL
        echo '<?xml version="1.0" encoding="UTF-8"?>'."\n";
        echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"'.
            ' "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">'."\n";
        echo '<html xmlns="http://www.w3.org/1999/xhtml">';
        echo '<head>
					<meta http-equiv="content-type" content="text/html; charset=utf-8">
					<title>Redirect</title>
				</head>';
        echo '<body>';
        echo '<h1>Redirect</h1>';
        echo '<p>';
        echo 'You were redirected to: ';
        echo '<a id="redirlink" href="'.
            htmlspecialchars($url).'">'.htmlspecialchars($url).'</a>';
        echo '<script type="text/javascript">document.getElementById("redirlink").focus();</script>';
        echo '</p>';
        echo '</body>';
        echo '</html>';

        // End script execution
        exit;
    }


    /**
     * @deprecated 1.12.0 This method will be removed from the API. Instead, use the redirectTrustedURL() or
     * redirectUntrustedURL() functions accordingly.
     * @param string $url
     * @param array $parameters
     * @param array|null $allowed_redirect_hosts
     * @return void
     */
    public static function redirect($url, $parameters = [], $allowed_redirect_hosts = null)
    {
        assert(is_string($url));
        assert(strlen($url) > 0);
        assert(is_array($parameters));

        if ($allowed_redirect_hosts !== null) {
            $url = self::checkURLAllowed($url, $allowed_redirect_hosts);
        } else {
            $url = self::normalizeURL($url);
        }
        self::doRedirect($url, $parameters);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::redirectTrustedURL()
     *     instead.
     * @param string $url
     * @param array $parameters
     * @return void
     */
    public static function redirectTrustedURL($url, $parameters = [])
    {
        HTTP::redirectTrustedURL($url, $parameters);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::redirectUntrustedURL()
     *     instead.
     * @param string $url
     * @param array $parameters
     * @return void
     */
    public static function redirectUntrustedURL($url, $parameters = [])
    {
        HTTP::redirectUntrustedURL($url, $parameters);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Arrays::transpose() instead.
     * @param array $in
     * @return mixed
     */
    public static function transposeArray($in)
    {
        return Arrays::transpose($in);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\XML::isDOMNodeOfType()
     *     instead.
     * @param DOMNode $element
     * @param string $name
     * @param string $nsURI
     * @return bool
     */
    public static function isDOMElementOfType(DOMNode $element, $name, $nsURI)
    {
        return XML::isDOMNodeOfType($element, $name, $nsURI);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\XML::getDOMChildren() instead.
     * @param DOMElement $element
     * @param string $localName
     * @param string $namespaceURI
     * @return array
     */
    public static function getDOMChildren(DOMElement $element, $localName, $namespaceURI)
    {
        return XML::getDOMChildren($element, $localName, $namespaceURI);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\XML::getDOMText() instead.
     * @param DOMNode $element
     * @return string
     */
    public static function getDOMText($element)
    {
        return XML::getDOMText($element);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::getAcceptLanguage()
     *     instead.
     * @return array
     */
    public static function getAcceptLanguage()
    {
        return HTTP::getAcceptLanguage();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\XML::isValid() instead.
     * @param string $xml
     * @param string $schema
     * @return string|false
     */
    public static function validateXML($xml, $schema)
    {
        $result = XML::isValid($xml, $schema);
        return ($result === true) ? '' : $result;
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\XML::checkSAMLMessage() instead.
     * @param string $message
     * @param string $type
     * @return void
     */
    public static function validateXMLDocument($message, $type)
    {
        XML::checkSAMLMessage($message, $type);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use openssl_random_pseudo_bytes() instead.
     * @param int $length
     * @return string
     */
    public static function generateRandomBytes($length)
    {
        assert(is_int($length));

        return openssl_random_pseudo_bytes($length);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use bin2hex() instead.
     * @param string $bytes
     * @return string
     */
    public static function stringToHex($bytes)
    {
        $ret = '';
        for ($i = 0; $i < strlen($bytes); $i++) {
            $ret .= sprintf('%02x', ord($bytes[$i]));
        }
        return $ret;
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\System::resolvePath() instead.
     * @param string $path
     * @param string|null $base
     * @return string
     */
    public static function resolvePath($path, $base = null)
    {
        return System::resolvePath($path, $base);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::resolveURL() instead.
     * @param string $url
     * @param string|null $base
     * @return string
     */
    public static function resolveURL($url, $base = null)
    {
        return HTTP::resolveURL($url, $base);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::normalizeURL() instead.
     * @param string $url
     * @return string
     */
    public static function normalizeURL($url)
    {
        return HTTP::normalizeURL($url);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::parseQueryString() instead.
     * @param string $query_string
     * @return array
     */
    public static function parseQueryString($query_string)
    {
        return HTTP::parseQueryString($query_string);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use
     * SimpleSAML\Utils\Attributes::normalizeAttributesArray() instead.
     * @param array $attributes
     * @return array
     */
    public static function parseAttributes($attributes)
    {
        return Attributes::normalizeAttributesArray($attributes);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Config::getSecretSalt() instead.
     * @return string
     */
    public static function getSecretSalt()
    {
        return Config::getSecretSalt();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please call error_get_last() directly.
     * @return string
     */
    public static function getLastError()
    {

        if (!function_exists('error_get_last')) {
            return '[Cannot get error message]';
        }

        $error = error_get_last();
        if ($error === null) {
            return '[No error message found]';
        }

        return $error['message'];
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Config::getCertPath() instead.
     * @param string $path
     * @return string
     */
    public static function resolveCert($path)
    {
        return Config::getCertPath($path);
    }


    /**
     * @param Configuration $metadata
     * @param bool $required
     * @param string $prefix
     * @return array|null
     *@deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Crypto::loadPublicKey() instead.
     */
    public static function loadPublicKey(Configuration $metadata, $required = false, $prefix = '')
    {
        return Crypto::loadPublicKey($metadata, $required, $prefix);
    }


    /**
     * @param Configuration $metadata
     * @param bool $required
     * @param string $prefix
     * @return array|null
     *@deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Crypto::loadPrivateKey() instead.
     */
    public static function loadPrivateKey(Configuration $metadata, $required = false, $prefix = '')
    {
        return Crypto::loadPrivateKey($metadata, $required, $prefix);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\XML::formatDOMElement() instead.
     * @param DOMElement $root
     * @param string $indentBase
     * @return void
     */
    public static function formatDOMElement(DOMElement $root, $indentBase = '')
    {
        XML::formatDOMElement($root, $indentBase);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\XML::formatXMLString() instead.
     * @param string $xml
     * @param string $indentBase
     * @return string
     */
    public static function formatXMLString($xml, $indentBase = '')
    {
        return XML::formatXMLString($xml, $indentBase);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Arrays::arrayize() instead.
     * @param mixed $data
     * @param int $index
     * @return array
     */
    public static function arrayize($data, $index = 0)
    {
        return Arrays::arrayize($data, $index);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Auth::isAdmin() instead.
     * @return bool
     */
    public static function isAdmin()
    {
        return Auth::isAdmin();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Auth::getAdminLoginURL instead();
     * @param string|null $returnTo
     * @return string
     */
    public static function getAdminLoginURL($returnTo = null)
    {
        return Auth::getAdminLoginURL($returnTo);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Auth::requireAdmin() instead.
     * @return void
     */
    public static function requireAdmin()
    {
        Auth::requireAdmin();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::submitPOSTData() instead.
     * @param string $destination
     * @param array $post
     * @return void
     */
    public static function postRedirect($destination, $post)
    {
        HTTP::submitPOSTData($destination, $post);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. PLease use SimpleSAML\Utils\HTTP::getPOSTRedirectURL()
     *     instead.
     * @param string $destination
     * @param array $post
     * @return string
     */
    public static function createPostRedirectLink($destination, $post)
    {
        return HTTP::getPOSTRedirectURL($destination, $post);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::getPOSTRedirectURL()
     *     instead.
     * @param string $destination
     * @param array $post
     * @return string
     * @throws Error If the current session is a transient session.
     */
    public static function createHttpPostRedirectLink($destination, $post)
    {
        assert(is_string($destination));
        assert(is_array($post));

        $postId = Random::generateID();
        $postData = [
            'post' => $post,
            'url'  => $destination,
        ];

        $session = Session::getSessionFromRequest();
        if ($session->isTransient()) {
            throw new Error('Cannot save data to a transient session');
        }

        $session->setData('core_postdatalink', $postId, $postData);

        $redirInfo = base64_encode(Crypto::aesEncrypt($session->getSessionId().':'.$postId));

        $url = Module::getModuleURL('core/postredirect.php', ['RedirInfo' => $redirInfo]);
        $url = preg_replace("#^https:#", "http:", $url);

        return $url;
    }


    /**
     * @deprecated This method will be removed in SSP 2.0.
     * @param string $certificate
     * @param string $caFile
     * @return void
     */
    public static function validateCA($certificate, $caFile)
    {
        Validator::validateCertificate($certificate, $caFile);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Time::initTimezone() instead.
     * @return void
     */
    public static function initTimezone()
    {
        Time::initTimezone();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\System::writeFile() instead.
     * @param string $filename
     * @param string $data
     * @param int $mode
     * @return void
     */
    public static function writeFile($filename, $data, $mode = 0600)
    {
        System::writeFile($filename, $data, $mode);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\System::getTempDir instead.
     * @return string
     */
    public static function getTempDir()
    {
        return System::getTempDir();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Logger::maskErrors() instead.
     * @param int $mask
     * @return void
     */
    public static function maskErrors($mask)
    {
        Logger::maskErrors($mask);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Logger::popErrorMask() instead.
     * @return void
     */
    public static function popErrorMask()
    {
        Logger::popErrorMask();
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use
     *     SimpleSAML\Utils\Config\Metadata::getDefaultEndpoint() instead.
     * @param array $endpoints
     * @param array|null $bindings
     * @return array|null
     */
    public static function getDefaultEndpoint(array $endpoints, array $bindings = null)
    {
        return Metadata::getDefaultEndpoint($endpoints, $bindings);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::checkSessionCookie()
     *     instead.
     * @param string|null $retryURL
     * @return void
     */
    public static function checkCookie($retryURL = null)
    {
        HTTP::checkSessionCookie($retryURL);
    }


    /**
     * @param string|DOMElement $message
     * @param string $type
     * @return void
     *@deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\XML::debugSAMLMessage() instead.
     */
    public static function debugMessage($message, $type)
    {
        XML::debugSAMLMessage($message, $type);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::fetch() instead.
     * @param string $path
     * @param array $context
     * @param bool $getHeaders
     * @return string|array
     */
    public static function fetch($path, $context = [], $getHeaders = false)
    {
        return HTTP::fetch($path, $context, $getHeaders);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Crypto::aesEncrypt() instead.
     * @param string $clear
     * @return string
     */
    public static function aesEncrypt($clear)
    {
        return Crypto::aesEncrypt($clear);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\Crypto::aesDecrypt() instead.
     * @param string $encData
     * @return string
     */
    public static function aesDecrypt($encData)
    {
        return Crypto::aesDecrypt($encData);
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\System::getOS() instead.
     * @return bool
     */
    public static function isWindowsOS()
    {
        return System::getOS() === System::WINDOWS;
    }


    /**
     * @deprecated This method will be removed in SSP 2.0. Please use SimpleSAML\Utils\HTTP::setCookie() instead.
     * @param string $name
     * @param string|null $value
     * @param array|null $params
     * @param bool $throw
     * @return void
     */
    public static function setCookie($name, $value, array $params = null, $throw = true)
    {
        HTTP::setCookie($name, $value, $params, $throw);
    }
}
