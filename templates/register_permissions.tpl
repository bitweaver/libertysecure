{* $Header$ *}
{strip}
<div class="floaticon">{bithelp}</div>

<div class="admin liberty">
	<div class="header">
		<h1>{tr}Register Default Permissions{/tr}</h1>
	</div>

	<div class="body">

		{form legend="Register Default Permissions" enctype="multipart/form-data"}
		{box class="libertymenu menu box" ipackage="libertysecure" iname="pkg_libertysecure" iexplain="LibertySecure" iclass="menuicon" title="LibertySecure"}
			{if $updated}
				<h2>{tr}Results{/tr}</h2>
				{if !$errors}
					{formfeedback success="All active package default permissions have been registered. You can now safely use Custom Content Permissions. Return to this page if you install any new packages."}
				{else}
					{formfeedback error="There was a problem."}
				{/if}
			{else}
				<p>LibertySecure augments the Liberty Package to support individual custom content permissions. Custom content permissions allow you to set unique permissions individual of the default group permissions on any Liberty based content, such as wiki pages, blog posts, etc. LibertySecure augements Liberty by registering the default View, Edit, and Admin permissions of all installed packages. Once those permissions are registered in the database you can safely begin using custom content permissions. You can register these default permissions by clicking the button below.</p> 
				<p>{formfeedback warning="Every time you install a new package you must rerun this Registration, or else you may experiece a security breach when using custom content permissions."}</p>
				<div class="form-group submit">
					<input type="submit" class="btn btn-default" name="register_perms" value="{tr}Register Permissions{/tr}" />
				</div>
			{/if}
		{/box}
		{/form}
	</div>
</div>
{/strip}
