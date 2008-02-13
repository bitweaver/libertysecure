<?php
/**
* $Header: /cvsroot/bitweaver/_bit_libertysecure/libertysecure_lib.php,v 1.2 2008/02/13 08:04:29 wjames5 Exp $
* @date created 2006/08/01
* @author Will <will@onnyturf.com>
* @version $Revision: 1.2 $ $Date: 2008/02/13 08:04:29 $
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
	global $gBitSystem, $gBitUser;
	$ret = array();
	$traceArr = debug_backtrace();
	array_shift($traceArr);
	foreach ($traceArr as $arr) {
		if (  $arr['function'] == 'getContentList' && !$gBitUser->isAdmin() ){
			// @TODO bugcheck  query
			// $ret['select_sql'] = ""; 
			$ret['join_sql'] = "LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_secure_permissions_map` lcpm ON ( lcpm.`content_type_guid` = lc.`content_type_guid` )
				LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_content_permissions` lcperm ON (lc.`content_id`=lcperm.`content_id`)
				LEFT OUTER JOIN `".BIT_DB_PREFIX."users_groups_map` ugsm ON ( ugsm.`group_id`=lcperm.`group_id`)
				LEFT OUTER JOIN `".BIT_DB_PREFIX."users_group_permissions` ugp ON ( ugsm.`group_id`=ugp.`group_id` )";
			$ret['bind_vars'] = array( $gBitUser->mUserId, 'y', $gBitUser->mUserId, 'view' );
			$ret['where_sql'] = " AND lcpm.content_type_guid IS NULL 
								OR  
								( ugp.group_id IS NOT NULL
									AND 
									( lcperm.perm_name IS NULL AND ( ugp.`perm_name` = lcpm.`perm_name` ) 
										OR 
										( lcperm.perm_name != lcpm.`perm_name`
										  OR 
										  ( lcperm.perm_name = lcpm.`perm_name` 
											AND 
											ugsm.user_id = ? 
											AND 
											(
												( lcperm.is_revoked != ? OR lcperm.is_revoked IS NULL) 
												OR 
												lc.`user_id`= ? 
											) 
										  ) 
										) 
									) 
									AND 
									( lcpm.`perm_type` = ? )
								)";  
			break;
		};
	}
	return $ret;
}

?>
