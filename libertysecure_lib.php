<?php
/**
* $Header: /cvsroot/bitweaver/_bit_libertysecure/libertysecure_lib.php,v 1.9 2008/03/04 14:03:51 nickpalmer Exp $
* @date created 2006/08/01
* @author Will <will@onnyturf.com>
* @version $Revision: 1.9 $ $Date: 2008/03/04 14:03:51 $
* @class LibertySecure
*/

function secure_register_permissions(){
	global $gBitSystem, $gLibertySystem;

	// these are the common basic permission types across packages
	$permissionTypes = array('view', 'edit', 'admin');

	// dump all perms in liberty_secure_permissions_map table
	$gBitSystem->mDb->query( "DELETE FROM `".BIT_DB_PREFIX."liberty_secure_permissions_map`" );

	// step through each loaded content types
	foreach( $gLibertySystem->mContentTypes as $type ){
		if ( isset($type['handler_package']) && isset( $type['handler_file'] ) && isset( $type['handler_class'] ) ){
			require_once( BIT_ROOT_PATH.$type['handler_package']."/".$type['handler_file'] );
			$class = $type['handler_class'];
			$content = new $class();
			foreach( $permissionTypes as $perm ){
				$contentPerm = "m".ucfirst($perm)."ContentPerm";
				// get default perms. Skip packages with defulat p_admin bs.
				if ( isset( $content->$contentPerm )  && isset( $content->mType['content_type_guid'] ) && $content->$contentPerm != 'p_admin_content' ){
					$bindVars = array();
					$bindVars[] = $perm;
					$bindVars[] = $content->$contentPerm;
					$bindVars[] = $content->mType['content_type_guid'];
					// store them in liberty_secure_permissions_map table
					$storeSql = "INSERT INTO `".BIT_DB_PREFIX."liberty_secure_permissions_map`(`perm_type`,`perm_name`,`content_type_guid`) VALUES (?,?,?)";
					$gBitSystem->mDb->query( $storeSql, $bindVars );
				}
			}
		}
	}
	return;
}


function secure_get_content_permissions( $pContentGuid ){
	global $gBitSystem, $gLiberySystem;
	$query = "SELECT lspm.`perm_type`, lspm.`perm_name` FROM `".BIT_DB_PREFIX."liberty_secure_permissions_map` lspm WHERE lspm.`content_type_guid`=?";
	$rslt = $gBitSystem->mDb->getAssoc( $query, array( $pContentGuid ) );
	return $rslt;
}


/********* SERVICE FUNCTIONS *********/

function secure_content_list_sql( &$pObject, $pParamHash=NULL ) {
	global $gBitSystem, $gBitUser;
	$ret = array();
	if (!$gBitUser->isAdmin()) {
		$groups = array_keys($gBitUser->mGroups);
		// Check that these are all integers just for safety. Assumes they have at least one group but all should have -1
		if ($gBitSystem->verifyId($groups)) {
			// Handy for debuging to see what is coming out
			//				$ret['select_sql'] = ", lcpm.`perm_name` AS lc_sec_target, lcpermgrnt.`perm_name` as lc_sec_grant, lcpermrev.`is_revoked` as lc_sec_revoke, ugpgc.`perm_name` AS lc_sec_default ";

			$ret['join_sql'] =
				// Get the permission name we need to target from here
				" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_secure_permissions_map` lcpm ON ( lcpm.`content_type_guid` = lc.`content_type_guid` AND lcpm.`perm_type` = 'view' )".
				// Check if a group is allowed by default
				" LEFT JOIN `".BIT_DB_PREFIX."users_group_permissions` ugpgc ON (ugpgc.`perm_name` = lcpm.`perm_name` AND ugpgc.`group_id` IN (".implode(',', $groups) .") )".
				// Check if the permission is granted
				" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_content_permissions` lcpermgrnt ON (lc.`content_id` = lcpermgrnt.`content_id` AND lcpermgrnt.`perm_name` = lcpm.`perm_name` AND  lcpermgrnt.`group_id` IN (".implode(',', $groups) .") AND lcpermgrnt.`is_revoked` IS NULL )".
				// Make sure the permission hasn't been revoked
				" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_content_permissions` lcpermrev ON (lc.`content_id` = lcpermrev.`content_id` AND lcpermrev.`perm_name` = lcpm.`perm_name` AND lcpermrev.`group_id` IN (".implode(',', $groups) .") AND lcpermrev.`is_revoked` = 'y' )";

			$ret['bind_vars'] = $gBitUser->mUserId;

			// Always revoke if revoked otherwise grant if we should
			$ret['where_sql'] = " AND (lc.`user_id` = ? OR lcpermgrnt.`perm_name` IS NOT NULL OR ( lcpermrev.`is_revoked` IS NULL AND ugpgc.`perm_name` IS NOT NULL) ) ";
		}
		else {
			// Somebody is attempting to hack group Ids. Give them NOTHING!
			$gBitSystem->fatalError('Invalid Group Id.');
		}
	};

	return $ret;
}

?>
