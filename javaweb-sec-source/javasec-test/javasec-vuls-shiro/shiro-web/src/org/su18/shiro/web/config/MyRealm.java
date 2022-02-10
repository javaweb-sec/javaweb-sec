package org.su18.shiro.web.config;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.ldap.JndiLdapRealm;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * @author su18
 */
public class MyRealm extends JndiLdapRealm {


	@Override
	protected AuthorizationInfo queryForAuthorizationInfo(PrincipalCollection principals, LdapContextFactory ldapContextFactory) throws NamingException {

		String username = (String) getAvailablePrincipal(principals);
		// Perform context search
		LdapContext ldapContext = ldapContextFactory.getSystemLdapContext();
		Set<String> roleNames;

		try {
			roleNames = getRoleNamesForUser(username, ldapContext);
		} finally {
			LdapUtils.closeContext(ldapContext);
		}

		return buildAuthorizationInfo(roleNames);
	}

	protected AuthorizationInfo buildAuthorizationInfo(Set<String> roleNames) {
		return new SimpleAuthorizationInfo(roleNames);
	}

	protected Set<String> getRoleNamesForUser(String username, LdapContext ldapContext) throws NamingException {
		Set<String> roleNames;
		roleNames = new LinkedHashSet<String>();

		SearchControls searchCtls = new SearchControls();
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		//SHIRO-115 - prevent potential code injection:
		String   searchFilter    = "(&(objectClass=*)(CN={0}))";
		Object[] searchArguments = new Object[]{username};

		//  Name searchBase;
		String                          searchBase = "test";
		NamingEnumeration<SearchResult> answer     = ldapContext.search(searchBase, searchFilter, searchArguments, searchCtls);

		while (answer.hasMoreElements()) {
			SearchResult sr = (SearchResult) answer.next();


			Attributes attrs = sr.getAttributes();

			if (attrs != null) {
				NamingEnumeration<? extends Attribute> ae = attrs.getAll();
				while (ae.hasMore()) {
					Attribute attr = (Attribute) ae.next();

					if (attr.getID().equals("memberOf")) {

						Collection<String> groupNames = LdapUtils.getAllAttributeValues(attr);


						Collection<String> rolesForGroups = getRoleNamesForGroups(groupNames);
						roleNames.addAll(rolesForGroups);
					}
				}
			}
		}
		return roleNames;
	}

	// active dir
	protected Collection<String> getRoleNamesForGroups(Collection<String> groupNames) {
		return new HashSet<String>(groupNames.size());
	}
}