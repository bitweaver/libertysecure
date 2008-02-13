<?php
$registerHash = array(
	'package_name' => 'libertysecure',
	'package_path' => dirname( __FILE__ ).'/',
	'service' => LIBERTY_SERVICE_LIBERTYSECURE,
);
$gBitSystem->registerPackage( $registerHash );

if( $gBitSystem->isPackageActive( 'libertysecure' ) ) {
	require_once( LIBERTYSECURE_PKG_PATH.'libertysecure_lib.php' );

	$gLibertySystem->registerService( LIBERTY_SERVICE_LIBERTYSECURE, LIBERTYSECURE_PKG_NAME, array(
		'content_list_sql_function' => 'secure_content_list_sql',
	) );
}
?>
