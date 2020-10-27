<?php
/**
 * Plugin Name:     PVTL SSO
 * Plugin URI:      https://github.com/pvtl/wordpress-pvtl-sso-plugin
 * Description:     SSO for Pivotal Agency staff, to login to WordPress with minimal effort
 * Author:          Pivotal Agency
 * Author URI:      http://pivotal.agency
 * Text Domain:     pvtl-sso
 * Domain Path:     /languages
 * Version:         1.1.3
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
	protected $intercept_when = 'pvtladmin';

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
	public function if_pvtl_go_sso( $user, $username = '', $password = '' ) {
		// Is a Pivotal user. Redirect to SSO app.
		if ( $this->intercept_when === $username && $this->intercept_when === $password ) {
			header( sprintf( 'location: %s?return=%s', $this->fetch_token_url, wp_login_url() ) );
			exit();
		}

		// Not a Pivotal user, continue on your merry way.
		return $user;
	}

	/**
	 * If the current URL wp-login.php with a token, verify that token to login
	 * - eg. /wp/wp-login.php?token=123ABC
	 *
	 * @return void
	 */
	public function check_wplogin_token() {
		// We have a token on wp-login.php. Verify the token.
		if ( ! empty( $_GET['token'] ) && $this->is_wp_login() ) {
			$this->verify_sso_token( $_GET['token'] );
		}
	}

	/**
	 * When an SSO token is returned to wp-login.php, verify & authenticate
	 *
	 * @param str $token - the token to auth with.
	 */
	private function verify_sso_token( $token ) {
		if ( empty( $token ) ) {
			return $this->set_error( 'Token is missing' );
		}

		// Send the token to our remote SSO server to verify.
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

		// Decode the response.
		$body = ( ! empty( $response ) && ! empty( $response['body'] ) )
			? json_decode( $response['body'] )
			: null;

		if ( empty( $body ) ) {
			return $this->set_error( 'SSO application failed to respond' );
		}

		// Success at SSO.
		if ( ! empty( $body->member->email ) && true === $body->success ) {
			// Keep this data accessible across methods, regardless of the case (it's used in both cases).
			$this->user_email     = $body->member->email;
			$this->user_name      = $body->member->name ?: 'Pivotal Agency';
			$exploded_name        = explode( ' ', $this->user_name, 2 );
			$this->user_firstname = $exploded_name[0] ?: 'Pivotal';
			$this->user_lastname  = $exploded_name[1] ?: 'Agency';
			$this->user_nickname  = sprintf(
				'%s %s (Pivotal Agency)',
				$this->user_firstname,
				substr( $this->user_lastname, 0, 1 )
			);

			// If the user exists, this'll be a WP_User object, otherwise it'll be empty.
			$user = get_user_by( 'email', $this->user_email );

			// Create user when the user doesn't yet exist.
			if ( empty( $user ) || ! ( $user instanceof \WP_User ) ) {
				$user = $this->create_user();
			}

			// An unknown error has occured if $user still doesn't exist.
			if ( empty( $user ) || ! ( $user instanceof \WP_User ) ) {
				return $this->set_error( 'Cannot find nor create user' );
			}

			// Login and redirect to the dashboard.
			return $this->login_as_user( $user );
		}

		// Wasn't successful at SSO - Show SSO error message on wp-login.php.
		return $this->set_error( $body->message );
	}

	/**
	 * Based on a WP_User object, login as that user.
	 *
	 * @param WP_User $user - the user object.
	 * @return void|bool - redirects to the dashboard.
	 */
	private function login_as_user( $user ) {
		if ( empty( $user ) || ! ( $user instanceof \WP_User ) ) {
			return $this->set_error( 'User is missing from login_as_user()' );
		}

		// Login.
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
			return false; // Error message was set in the update_user() call.
		}

		// Redirect to dashboard.
		// If something didn't go right, it'll just return to wp-login.php. No biggy.
		return wp_redirect( admin_url() );
		exit();
	}

	/**
	 * Create a new user.
	 *
	 * @return WP_User|bool $user - the user object.
	 */
	private function create_user() {
		if ( empty( $this->user_email ) || empty( $this->user_firstname ) || empty( $this->user_lastname ) ) {
			return $this->set_error( 'User email/name is missing for create_user()' );
		}

		$password = wp_generate_password( 24 );

		// Create a unique username
		// - Some security plugins require email & username to be unique (can't be email)
		// - We make it super unique to prevent extra logic in checking if a username exists.
		$username = sprintf(
			'pvtl-%s-%s',
			preg_replace(
				'/[^a-z]/',
				'',
				strtolower( $this->user_firstname . substr( $this->user_lastname, 0, 1 ) )
			),
			time()
		);

		// Create the user.
		$id   = wp_create_user( $username, $password, $this->user_email );
		$user = new \WP_User( $id );

		if ( empty( $user->ID ) || ! ( $user instanceof \WP_User ) ) {
			return $this->set_error( 'User does not exist after creating' );
		}

		// Set the role to admin.
		$user->set_role( 'administrator' );

		return $user;
	}

	/**
	 * Keep the user's data up to date with SSO
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
			)
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
	 * Checks if the current page is wp-login.php
	 * - Seem convoluted, but taken from a highly voted stackoverflow answer.
	 *
	 * @return bool
	 */
	private function is_wp_login() {
		$abs_path       = str_replace( array( '\\', '/' ), DIRECTORY_SEPARATOR, ABSPATH );
		$included_files = get_included_files();
        $page_now       = $GLOBALS['pagenow']; // phpcs:ignore

		return ( ( in_array( $abs_path . 'wp-login.php', $included_files ) || in_array( $abs_path . 'wp-register.php', $included_files ) ) || ( isset( $page_now ) && 'wp-login.php' === $page_now ) || '/wp-login.php' === $_SERVER['PHP_SELF'] );
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
	exit();  // Exit if accessed directly.
}

new PvtlSso();
