<?php
/**
* $Header: /cvsroot/bitweaver/_bit_libertysecure/libertysecure_lib.php,v 1.14 2008/04/21 22:32:25 wjames5 Exp $
* @date created 2006/08/01
* @author Will <will@onnyturf.com>
* @version $Revision: 1.14 $ $Date: 2008/04/21 22:32:25 $
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
	if (!$gBitUser->isAdmin() && !( isset( $pParamHash['has_comment_view_perm'] ) && $pParamHash['has_comment_view_perm'] == TRUE) ) {
		$groups = array_keys($gBitUser->mGroups);
		// Check that these are all integers just for safety. Assumes they have at least one group but all should have -1
		if ($gBitSystem->verifyId($groups)) {
			// Handy for debuging to see what is coming out
			// $ret['select_sql'] = ", lcpm.`perm_name` AS lc_sec_target, lcpermgrnt.`perm_name` as lc_sec_grant, lcpermrev.`is_revoked` as lc_sec_revoke, ugpgc.`perm_name` AS lc_sec_default ";

			$ret['join_sql'] =
				// Get the permission name we need to target from here
				" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_secure_permissions_map` lcpm ON ( lcpm.`content_type_guid` = lc.`content_type_guid` AND lcpm.`perm_type` = 'view' )".
				// Check if a group is allowed by default
				" LEFT JOIN `".BIT_DB_PREFIX."users_group_permissions` ugpgc ON (ugpgc.`perm_name` = lcpm.`perm_name` AND ugpgc.`group_id` IN (".implode(',', $groups) .") )".
				// Check if the permission is granted
				" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_content_permissions` lcpermgrnt ON (lc.`content_id` = lcpermgrnt.`content_id` AND lcpermgrnt.`perm_name` = lcpm.`perm_name` AND  lcpermgrnt.`group_id` IN (".implode(',', $groups) .") AND lcpermgrnt.`is_revoked` IS NULL )".
				// Make sure the permission hasn't been revoked
				" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_content_permissions` lcpermrev ON (lc.`content_id` = lcpermrev.`content_id` AND lcpermrev.`perm_name` = lcpm.`perm_name` AND lcpermrev.`group_id` IN (".implode(',', $groups) .") AND lcpermrev.`is_revoked` = 'y' )";

			$ret['bind_vars'] = array( $gBitUser->mUserId );

			// Always revoke if revoked otherwise grant if we should
			// Note: AND is added after comments stuff
			$ret['where_sql'] = " ( lc.`content_type_guid` != 'bitcomment' AND (lc.`user_id` = ? OR lcpermgrnt.`perm_name` IS NOT NULL OR ( lcpermrev.`is_revoked` IS NULL AND ugpgc.`perm_name` IS NOT NULL) ) ) ";

			// Comments add considerable expense. Don't do it unless we have to
			// sometimes content_type_guid is a string and sometimes its an array - deal with it.
			$content_types = array();
			if ( !empty( $pParamHash['content_type_guid'] ) ){
				$content_types = is_array( $pParamHash['content_type_guid'] )?$pParamHash['content_type_guid']:array( $pParamHash['content_type_guid'] );
			}
			if (!empty($pParamHash['include_comments']) || in_array('bitcomment', $content_types) ) {
				// Handy for debuging to see what is coming out
				// $ret['select_sql'] = ", lcomm.content_id AS comment_content_id, lc2.`content_id` AS root_content_id, lcpm2.`perm_name` AS lc_sec_target2, lcpermgrnt2.`perm_name` as lc_sec_grant2, lcpermrev2.`is_revoked` as lc_sec_revoke2, ugpgc2.`perm_name` AS lc_sec_default2 ";

				$ret['join_sql'] .=
					// Get the parent content type
					" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_comments` lcomm ON (lc.`content_id` = lcomm.`content_id`)".
					" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_content` lc2 ON (lcomm.`root_id` = lc2.`content_id`)".
					// Get the permission name we need to target from here
					" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_secure_permissions_map` lcpm2 ON ( lcpm2.`content_type_guid` = lc2.`content_type_guid` AND lcpm2.`perm_type` = 'view' )".
					// Check if a group is allowed by default
					" LEFT JOIN `".BIT_DB_PREFIX."users_group_permissions` ugpgc2 ON (ugpgc2.`perm_name` = lcpm2.`perm_name` AND ugpgc2.`group_id` IN (".implode(',', $groups) .") )".
					// Check if the permission is granted
					" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_content_permissions` lcpermgrnt2 ON (lc2.`content_id` = lcpermgrnt2.`content_id` AND lcpermgrnt2.`perm_name` = lcpm2.`perm_name` AND  lcpermgrnt2.`group_id` IN (".implode(',', $groups) .") AND lcpermgrnt2.`is_revoked` IS NULL )".
					// Make sure the permission hasn't been revoked
					" LEFT OUTER JOIN `".BIT_DB_PREFIX."liberty_content_permissions` lcpermrev2 ON (lc2.`content_id` = lcpermrev2.`content_id` AND lcpermrev2.`perm_name` = lcpm2.`perm_name` AND lcpermrev2.`group_id` IN (".implode(',', $groups) .") AND lcpermrev2.`is_revoked` = 'y' )";

				// Replace with new array which handles both where ?s
				$ret['bind_vars'] = array( $gBitUser->mUserId, $gBitUser->mUserId );

				// Always revoke if revoked otherwise grant if we should
				// Note: AND added below
				$ret['where_sql'] = " ( " . $ret['where_sql'] . " OR " .
					" ( lc.`content_type_guid` = 'bitcomment' AND ( lc2.`user_id` = ? OR lcpermgrnt2.`perm_name` IS NOT NULL OR ( lcpermrev2.`is_revoked` IS NULL AND ugpgc2.`perm_name` IS NOT NULL) ) ) )";
			}

			// Make sure to include the AND
			$ret['where_sql'] = " AND " . $ret['where_sql'];
		}
		else {
			// Somebody is attempting to hack group Ids. Give them NOTHING!
			$gBitSystem->fatalError('Invalid Group Id.');
		}
	};

	return $ret;
}

?>
