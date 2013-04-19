<?php
require_once( '../../kernel/setup_inc.php' );

$gBitSystem->verifyPermission( 'p_admin' );

/* this will clear out all permissions in the libertysecure_perms table 
 * then it will then reload them all in.
 */
if( !empty( $_REQUEST['register_perms'] ) ) {
	secure_register_permissions();
	// @TODO would be nice to have a way to get errors.
	/*
	if ( $errors ){
		$gBitSmarty->assign_by_ref( 'errors', $errors );
	}
	*/
	$gBitSmarty->assign( 'updated', TRUE );
}
$gBitSystem->display( 'bitpackage:libertysecure/register_permissions.tpl', tra( 'LibertySecure Register Permissions' ), array( 'display_mode' => 'admin' ));
?>
