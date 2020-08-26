<?php

namespace SAML\Auth;

use Exception;
use SAML\Logger;
use SAML\Module\ldap\Auth\Ldap;

Logger::warning("The class \SimpleSAML\Auth\LDAP has been moved to the ldap module, please use \SimpleSAML\Module\saml\Auth\Ldap instead.");

/**
 * @deprecated To be removed in 2.0
 */
if (class_exists('\SimpleSAML\Module\ldap\Auth\Ldap')) {
    class_alias(Ldap::class, 'SimpleSAML\Auth\LDAP');
} else {
    throw new Exception('The ldap module is either missing or disabled');
}
