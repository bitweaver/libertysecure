<?php
/**
* $Header: /cvsroot/bitweaver/_bit_libertysecure/libertysecure_lib.php,v 1.1 2008/02/13 00:52:28 wjames5 Exp $
* @date created 2006/08/01
* @author Will <will@onnyturf.com>
* @version $Revision: 1.1 $ $Date: 2008/02/13 00:52:28 $
* @class LibertySecure
*/

function secure_register_permissions(){
	global $gBitSystem, $gBitDb, $gLibertySystem;

	// these are the common basic permission types across packages
	$permissionTypes = array('view', 'edit', 'admin');

	// dump all perms in liberty_secure_permissions_map table
	$gBitDb->query( "DELETE FROM `".BIT_DB_PREFIX."liberty_secure_permissions_map`" );

	// step through each loaded content types
	foreach( $gLibertySystem->mContentTypes as $type ){
		if ( isset($type['handler_package']) && isset( $type['handler_file'] ) && isset( $type['handler_class'] ) ){
			require_once( BIT_ROOT_PATH.$type['handler_package']."/".$type['handler_file'] );
			$class = $type['handler_class'];
			$content = new $class();
			$storeSql = "INSERT INTO";
			foreach( $permissionTypes as $perm ){
				$contentPerm = "m".ucfirst($perm)."ContentPerm";
				// get default perms
				if ( isset( $content->$contentPerm )  && isset( $content->mType['content_type_guid'] ) ){
					$bindVars = array();
					$bindVars[] = $perm;
					$bindVars[] = $content->$contentPerm;
					$bindVars[] = $content->mType['content_type_guid'];
					// store them in liberty_secure_permissions_map table
					$storeSql = "INSERT INTO `".BIT_DB_PREFIX."liberty_secure_permissions_map`(`perm_type`,`perm_name`,`content_type_guid`) VALUES (?,?,?)";
					$gBitDb->mDb->query( $storeSql, $bindVars );
				}
			}
		}
	}
	return;
}


/********* SERVICE FUNCTIONS *********/

function secure_content_list_sql( &$pObject, $pParamHash=NULL ) {
	global $gBitSystem;
	$ret = array();
	$traceArr = debug_backtrace();
	array_shift($traceArr);
	foreach ($traceArr as $arr) {
		if (  $arr['function'] == 'getContentList' ){
			// @TODO add to query
			/*
			$ret['select_sql'] = ""; 
			$ret['join_sql'] = "";
			$ret['bind_vars'][] = ;
			 */
			break;
		};
	}
	return $ret;
}

?>
