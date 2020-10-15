<?php
/**
 * Plugin Name:     PVTL SSO
 * Plugin URI:      https://github.com/pvtl/wordpress-pvtl-sso-plugin
 * Description:     SSO for Pivotal Agency staff, to login to WordPress with minimal effort
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
	 * The username/password to kick things off.
	 *
	 * @var string
	 */
	protected $intercept_when = 'pvtl';

	/**
	 * The URL to access SSO application.
	 *
	 * @var string
	 */
	protected $fetch_token_url = 'https://projects2.nbm.is/sso/create_token.php';

	/**
	 * The URL to verify the token.
	 *
	 * @var string
	 */
	protected $verify_token_url = 'https://projects2.nbm.is/sso/check_token.php';

	/**
	 * Constructor
	 */
	public function __construct() {
		// Call the actions/hooks.
		add_filter( 'authenticate', array( $this, 'if_pvtl_go_sso' ), 20, 3 );
		add_filter( 'wp_loaded', array( $this, 'check_wplogin_token' ) );
	}

	/**
	 * Redirect to SSO if user is attempting to authenticate as a Pivotal user
	 *
	 * @param null|WP_User|WP_Error $user - the user object if successful.
	 * @param string                $username - username used to login.
	 * @param string                $password - password used to login.
	 */
	public function if_pvtl_go_sso( $user, $username, $password ) {
		// Is a Pivotal user. Redirect to SSO app.
		if ( $this->intercept_when === $username && $this->intercept_when === $password ) {
			$return_url = ( isset( $_SERVER['HTTPS'] ) && 'on' === $_SERVER['HTTPS'] ? 'https' : 'http' ) . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";

			return header( sprintf( 'location: %s?return=%s', $this->fetch_token_url, $return_url ) );
		}

		// Not a Pivotal user, continue on your merry way.
		return $user;
	}

	/**
	 * Is the current URL wp-login.php?
	 *
	 * @return void
	 */
	public function check_wplogin_token() {
		// Does a token URL param exist?
		if ( ! empty( $_GET['token'] ) ) {
			// It does. Is the current page wp-login?
			$abs_path       = str_replace( array( '\\', '/' ), DIRECTORY_SEPARATOR, ABSPATH );
			$included_files = get_included_files();
			$page_now = $GLOBALS['pagenow']; // phpcs:ignore

			$is_wplogin = ( ( in_array( $abs_path . 'wp-login.php', $included_files ) || in_array( $abs_path . 'wp-register.php', $included_files ) ) || ( isset( $page_now ) && 'wp-login.php' === $page_now ) || '/wp-login.php' === $_SERVER['PHP_SELF'] );

			// We have a token on wp-login. Authenticate.
			if ( $is_wplogin ) {
				$this->auth_with_sso_token( $_GET['token'] );
			}
		}
	}

	/**
	 * When an SSO token is returned to wp-login.php, authenticate
	 *
	 * @param str $token - the token to auth with.
	 */
	private function auth_with_sso_token( $token = '' ) {
		global $error;

		$response = wp_remote_post(
			$this->verify_token_url,
			array(
				'body' => array(
					'token_hash' => $token,
					'domain'     => $_SERVER['HTTP_HOST'],
					'ip'         => $_SERVER['REMOTE_ADDR'],
					'useragent'  => $_SERVER['HTTP_USER_AGENT'],
				),
			)
		);

		$body = ( ! empty( $response ) && ! empty( $response['body'] ) )
			? json_decode( $response['body'] )
			: null;

		// Success at SSO.
		if ( ! empty( $body->member->email ) && true === $body->success ) {
			// If the user exists, this'll be a user object, otherwise empty.
			$user = get_user_by( 'email', $body->member->email );

			// Create user if it doesn't exist.
			if ( empty( $user ) ) {
				$user = $this->create_user( $body->member->name, $body->member->email );
			}

			// Login and redirect to the dashboard.
			$this->login_as_user( $user );
		}

		// Wasn't successful at SSO - Show error message on wp-login.php.
		$error = $body->message; // phpcs:ignore
	}

	/**
	 * Based on an email, login as that user.
	 *
	 * @param WP_User $user - the user object.
	 * @return void - redirects to the dashboard.
	 */
	private function login_as_user( $user ) {
		wp_signon(
			array(
				'user_login' => $user->user_login,
				// We'll rotate the password, to prevent users manually changing it to get past SSO.
				'user_password' => $this->rotate_password( $user ),
			)
		);

		wp_redirect( admin_url() );
	}

	/**
	 * Create a new user.
	 *
	 * @param str $name - name of the new user.
	 * @param str $email - email of the new user.
	 * @return WP_User $user - the user object.
	 */
	private function create_user( $name = 'Pivotal', $email ) {
		// Create a unique username
		// - Some security plugins require email & username to be unique
		// - We make it super unique to prevent extra logic in checking if a username exists
		// - Sometimes the member name doesn't come back from SSO.
		$username = sprintf(
			'pvtl-%s-%s',
			preg_replace( '/[^a-z]/', '', strtolower( $name ) ),
			time()
		);
		$password = wp_generate_password( 24 );

		// Create the user.
		$id = wp_create_user( $username, $password, $email );

		// Set the role to admin.
		$user = new \WP_User( $id );
		$user->set_role( 'admin' );

		return $user;
	}

	/**
	 * Changes a user's password to something strong and unique.
	 *
	 * @param WP_User $user - the user object.
	 * @return null|str
	 */
	private function rotate_password( $user ) {
		$password = wp_generate_password( 24 );
		wp_set_password( $password, $user->ID );

		return $password;
	}
}

if ( ! defined( 'ABSPATH' ) ) {
	exit;  // Exit if accessed directly.
}

$pvtl_sso = new PVTLSSO();
