<?php
$tables = array(
  'liberty_secure_permissions_map' => "
	perm_name C(30) PRIMARY,
	perm_type C(30) PRIMARY,
	content_type_guid C(16) PRIMARY
		CONSTRAINT ', CONSTRAINT `libertysecure_perm_name_ref` FOREIGN KEY (`perm_name`) REFERENCES `".BIT_DB_PREFIX."users_permissions`( `perm_name` )
					, CONSTRAINT `libertysecure_content_type_ref` FOREIGN KEY (`content_type_guid`) REFERENCES `".BIT_DB_PREFIX."liberty_content_types`( `content_type_guid` )'
  "
);

global $gBitInstaller;

foreach( array_keys( $tables ) AS $tableName ) {
	$gBitInstaller->registerSchemaTable( LIBERTYSECURE_PKG_NAME, $tableName, $tables[$tableName] );
}

$gBitInstaller->registerPackageInfo( LIBERTYSECURE_PKG_NAME, array(
	'description' => "This package secures liberty content list queries when using custom content permissions. This package is required to use custom content permissions.",
	'license' => '<a href="http://www.gnu.org/licenses/licenses.html#LGPL">LGPL</a>',
) );
?>
