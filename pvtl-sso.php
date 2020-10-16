<?php
/**
 * Plugin Name:     PVTL SSO
 * Plugin URI:      https://github.com/pvtl/wordpress-pvtl-sso-plugin
 * Description:     SSO for Pivotal Agency staff, to login to WordPress with minimal effort
 * Author:          Pivotal Agency
 * Author URI:      http://pivotal.agency
 * Text Domain:     pvtl-sso
 * Domain Path:     /languages
 * Version:         1.0.0
 *
 * @package         PVTL_SSO
 */

namespace App\Plugins\Pvtl;

/**
 * Pivotal Agency Single Sign On Plugin
 */
class PvtlSso {
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
	protected $fetch_token_url = 'https://sso.pvtl.io/sso/create_token.php';

	/**
	 * The URL to verify the token.
	 *
	 * @var string
	 */
	protected $verify_token_url = 'https://sso.pvtl.io/sso/check_token.php';

	/**
	 * User's email.
	 *
	 * @var string
	 */
	protected $user_email = '';

	/**
	 * User's full name.
	 *
	 * @var string
	 */
	protected $user_name = '';

	/**
	 * User's first name.
	 *
	 * @var string
	 */
	protected $user_firstname = '';

	/**
	 * User's last name.
	 *
	 * @var string
	 */
	protected $user_lastname = '';

	/**
	 * User's nickname/display name.
	 *
	 * @var string
	 */
	protected $user_nickname = '';

	/**
	 * Constructor
	 */
	public function __construct() {
		// Add the filters to WP.
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
	public function if_pvtl_go_sso( $user, $username, $password = '' ) {
		// Is a Pivotal user. Redirect to SSO app.
		if ( $this->intercept_when === $username ) {
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
			// Taken from a highly voted stackoverflow answer.
			$abs_path       = str_replace( array( '\\', '/' ), DIRECTORY_SEPARATOR, ABSPATH );
			$included_files = get_included_files();
			$page_now = $GLOBALS['pagenow']; // phpcs:ignore

			$is_wplogin = ( ( in_array( $abs_path . 'wp-login.php', $included_files ) || in_array( $abs_path . 'wp-register.php', $included_files ) ) || ( isset( $page_now ) && 'wp-login.php' === $page_now ) || '/wp-login.php' === $_SERVER['PHP_SELF'] );

			// We have a token on wp-login.php. Verify the token.
			if ( $is_wplogin ) {
				$this->verify_sso_token( $_GET['token'] );
			}
		}
	}

	/**
	 * When an SSO token is returned to wp-login.php, authenticate
	 *
	 * @param str $token - the token to auth with.
	 */
	private function verify_sso_token( $token ) {
		if ( empty( $token ) ) {
			return $this->set_error( 'Token is missing' );
		}

		$response = wp_remote_post(
			$this->verify_token_url,
			array(
				'body' => array(
					'token_hash' => urlencode( $token ),
					'domain'     => $_SERVER['HTTP_HOST'],
					'ip'         => $_SERVER['REMOTE_ADDR'],
					'useragent'  => $_SERVER['HTTP_USER_AGENT'],
				),
			)
		);

		// Decode response.
		$body = ( ! empty( $response ) && ! empty( $response['body'] ) )
			? json_decode( $response['body'] )
			: null;

		if ( empty( $body ) ) {
			return $this->set_error( 'SSO application failed to respond' );
		}

		// Success at SSO.
		if ( ! empty( $body->member->email ) && true === $body->success ) {
			// Keep this data accessible across methods.
			$this->user_email     = $body->member->email;
			$this->user_name      = $body->member->name ?: 'Pivotal Agency';
			$exploded_name        = explode( ' ', $this->user_name, 2 );
			$this->user_firstname = $exploded_name[0] ?: 'Pivotal';
			$this->user_lastname  = $exploded_name[1] ?: 'Agency';
			$this->user_nickname  = sprintf(
				'%s %s (Pivotal Agency)',
				$this->user_firstname,
				substr( $this->user_lastname, 0, 1 ),
			);

			// If the user exists, this'll be a user object, otherwise it'll be empty.
			$user = get_user_by( 'email', $this->user_email );

			// Create user if it doesn't exist.
			if ( empty( $user ) || ! ( $user instanceof \WP_User ) ) {
				$user = $this->create_user();
			}

			// An unknown error has occured if $user still doesn't exist.
			if ( empty( $user ) || ! ( $user instanceof \WP_User ) ) {
				return $this->set_error( 'Cannot find or create user' );
			}

			// Login and redirect to the dashboard.
			return $this->login_as_user( $user );
		}

		// Wasn't successful at SSO - Show SSO error message on wp-login.php.
		return $this->set_error( $body->message );
	}

	/**
	 * Based on an email, login as that user.
	 *
	 * @param WP_User $user - the user object.
	 * @return void|bool - redirects to the dashboard.
	 */
	private function login_as_user( $user ) {
		if ( empty( $user ) || ! ( $user instanceof \WP_User ) ) {
			return $this->set_error( 'User is missing from login_as_user()' );
		}

		// Login!
		$logged_in_as = wp_signon(
			array(
				'user_login'    => $user->user_login,
				// We'll rotate the password, to prevent users manually changing it to get past SSO.
				'user_password' => $this->rotate_password( $user->ID ),
			)
		);

		if ( empty( $logged_in_as ) || ! ( $logged_in_as instanceof \WP_User ) ) {
			return $this->set_error( 'User is empty after attempting log in' );
		}

		// Update the user on each login, to keep the user's data up to date.
		if ( ! $this->update_user( $user->ID ) ) {
			return false; // Error message was set in update_user().
		}

		// Redirect to dashboard.
		// If something didn't go right, it'll just return to wp-login.php.
		return wp_redirect( admin_url() );
	}

	/**
	 * Create a new user.
	 *
	 * @return WP_User|bool $user - the user object.
	 */
	private function create_user() {
		if ( empty( $this->user_email ) || empty( $this->user_firstname ) || empty( $this->user_lastname ) ) {
			return $this->set_error( 'User email/name is missing from create_user()' );
		}

		$password = wp_generate_password( 24 );

		// Create a unique username
		// - Some security plugins require email & username to be unique
		// - We make it super unique to prevent extra logic in checking if a username exists
		// - Sometimes the member name doesn't come back from SSO.
		$username = sprintf(
			'pvtl-%s-%s',
			preg_replace(
				'/[^a-z]/',
				'',
				strtolower( $this->user_firstname . substr( $this->user_lastname, 0, 1 ) ),
			),
			time()
		);

		// Create the user.
		$id = wp_create_user( $username, $password, $this->user_email );

		// Set the role to admin.
		$user = new \WP_User( $id );

		if ( empty( $user->ID ) || ! ( $user instanceof \WP_User ) ) {
			return $this->set_error( 'User is empty after creating' );
		}

		$user->set_role( 'administrator' );

		return $user;
	}

	/**
	 * Keep the user's data up to date, from SSO
	 *
	 * @param int $user_id - The user's ID.
	 * @return void|bool
	 */
	private function update_user( $user_id ) {
		if ( empty( $user_id ) ) {
			return $this->set_error( 'User ID missing in update_user()' );
		}

		$id_of_updated_user = wp_update_user(
			array(
				'ID'           => $user_id,
				'first_name'   => $this->user_firstname,
				'last_name'    => $this->user_lastname,
				'nickname'     => $this->user_nickname,
				'display_name' => $this->user_nickname,
				'user_url'     => 'https://www.pivotalagency.com.au',
			),
		);

		if ( ! is_int( $id_of_updated_user ) ) {
			return $this->set_error( 'Could not update user' );
		}

		return true;
	}

	/**
	 * Changes a user's password to something strong and unique.
	 *
	 * @param int $user_id - The user's ID.
	 * @return null|str
	 */
	private function rotate_password( $user_id ) {
		$password = wp_generate_password( 24 );
		wp_set_password( $password, $user_id ); // Unfortunately doesn't return anything to check against.

		return $password;
	}

	/**
	 * Set an error message for wp-login.php
	 *
	 * @param str $message - The error message.
	 * @return bool
	 */
	private function set_error( $message ) {
		global $error;

		if ( empty( $error ) ) {
			$error = $message; // phpcs:ignore
		} else {
			$error = sprintf( '%s, %s', $error, $message ); // phpcs:ignore
		}

		return false;
	}
}

if ( ! defined( 'ABSPATH' ) ) {
	exit;  // Exit if accessed directly.
}

new PvtlSso();
