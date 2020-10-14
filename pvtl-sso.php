<?php
/**
 * Plugin Name:     PVTL SSO by Pivotal
 * Plugin URI:      https://github.com/pvtl/wordpress-pvtl-sso-plugin
 * Description:     SSO for Pivotal Agency staff, to login to Wordpress with minimal effort
 * Author:          Pivotal Agency
 * Author URI:      http://pivotal.agency
 * Text Domain:     pvtl-sso
 * Domain Path:     /languages
 * Version:         0.1.0
 *
 * @package         PVTL_SSO
 */

namespace App\Plugins\Pvtl;

/**
 * Pivotal Agency Single Sign On Plugin
 */
class PVTLSSO {
	/**
	 * The name of the plugin (for cosmetic purposes).
	 *
	 * @var string
	 */
	protected $plugin_name = 'PVTL SSO';

	/**
	 * Constructor
	 */
	public function __construct() {
		// Call the actions/hooks.
	}
}

if ( ! defined( 'ABSPATH' ) ) {
	exit;  // Exit if accessed directly.
}

$pvtl_sso = new PVTLSSO();
