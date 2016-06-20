package hello;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;



@RestController
public class AccountController {

	// @RequestMapping(value ="/authenticate", method = RequestMethod.GET)
	@RequestMapping(value = "/authenticate", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
	public UserDTO authenticate(@RequestParam(name = "user", defaultValue = "user") String user, @RequestParam(name = "password", defaultValue = "password") String pass) {
		String username = "corali";
		String password = "Welcome123";
		String base = "DC=apps-sgs,DC=com";
		String dn = "uid=" + username + "," + base;
		String ldapURL = "ldap://ad.internal.satoglobalsolutions.com:389/DC=apps-sgs,DC=com";

		// Setup environment for authenticating

		Hashtable<String, String> environment = new Hashtable<String, String>();
		environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		environment.put(Context.PROVIDER_URL, ldapURL);
		environment.put(Context.SECURITY_AUTHENTICATION, "simple");
		environment.put(Context.SECURITY_PRINCIPAL, username);
		environment.put(Context.SECURITY_CREDENTIALS, password);
		//environment.put(Context.SECURITY_PROTOCOL, "ssl");
		
//		Hashtable env = new Hashtable();
//		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
//		env.put(Context.PROVIDER_URL, ldapURL);
//
//		// Use anonymous authentication
//		env.put(Context.SECURITY_AUTHENTICATION, "none");

		// Create the initial context
		
		try {
			//DirContext ctx = new InitialDirContext(env);
			DirContext authContext = new InitialDirContext(environment);
			//return new UserDTO("javi", "ADMIN", "Javier Barriere");
		
		}catch (AuthenticationException ex) {
			ex.printStackTrace();
		} catch (NamingException ex) {
			ex.printStackTrace();
		}
		return new UserDTO();
		
	}


	@RequestMapping(value = "/authenticate1", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
	public @ResponseBody UserDTO authenticate1(@RequestBody AutenticateDTO credentials)  {
		final String ldapAdServer = "ldap://ad.internal.satoglobalsolutions.com:389";
		final String ldapSearchBase = "DC=apps-sgs,DC=com";

		final String ldapUsername = "corali";
		final String ldapPassword = "Welcome123";

		final String ldapAccountToLookup = credentials.getUser();

		Hashtable<String, Object> env = new Hashtable<String, Object>();
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
		env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapAdServer);
		
		// ensures that objectSID attribute values will be returned as a byte[]
		// instead of a String
		env.put("java.naming.ldap.attributes.binary", "objectSID");

		// the following is helpful in debugging errors
		env.put("com.sun.jndi.ldap.trace.ber", System.err);
		
		UserDTO user = new UserDTO();
		try {
			
			DirContext authContext = new InitialDirContext(env);
			AccountController ldap = new AccountController();

			// 1) lookup the ldap account
			SearchResult srLdapUser = ldap.findAccountByAccountName(authContext, ldapSearchBase, ldapAccountToLookup);
			//SearchResult srLdapUser = ldap.findAccountByAccountName(authContext, ldapSearchBase, ldapAccountToLookup);
			if(srLdapUser==null)
				return new UserDTO();
			user.setName((String) srLdapUser.getAttributes().get("displayname").get());
			user.setEmail((String) srLdapUser.getAttributes().get("mail").get());
			user.setUserName((String) srLdapUser.getAttributes().get("sAMAccountName").get());
			user.setGroups(ldap.getUserGroups(authContext, srLdapUser));
			//user.setRole(getUserOU(authContext, srLdapUser)[1]);
			return user;
			
		} catch (AuthenticationException ex) {
			ex.printStackTrace();
		} catch (NamingException ex) {
			ex.printStackTrace();
		}
		return new UserDTO();
	}

	public SearchResult findAccountByAccountName(DirContext ctx, String ldapSearchBase, String accountName)
			throws NamingException {

		String searchFilter = "(&(objectClass=user)(sAMAccountName=" + accountName + "))";

		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		NamingEnumeration<SearchResult> results = ctx.search(ldapSearchBase, searchFilter, searchControls);

		SearchResult searchResult = null;
		if (results.hasMoreElements()) {
			searchResult = (SearchResult) results.nextElement();

			// make sure there is not another item available, there should be
			// only 1 match
			if (results.hasMoreElements()) {
				System.err.println("Matched multiple users for the accountName: " + accountName);
				return null;
			}
		}
		return searchResult;
	}

//public String[] getUserOU(DirContext ctx,SearchResult srLdapUser) throws NamingException 
//{
//		
//		List<String> oUnits = new ArrayList<String>();
//        Attribute dName = srLdapUser.getAttributes().get("OU");
//        if (dName != null) 
//        { // null if this user belongs to no group at all
//            for (int i = 0; i < dName.size(); i++) 
//            {
//                Attributes atts = ctx.getAttributes(dName.get(i).toString(), new String[] { "OU" });
//                Attribute att = atts.get("OU");
//                if(att!=null) 
//                	oUnits.add(att.get().toString());
//            }
//        }
//        return oUnits.toArray(new String[oUnits.size()]);
//}

	public String[] getUserGroups(DirContext ctx,SearchResult srLdapUser) throws NamingException {
		
		List<String> groups = new ArrayList<String>();
        Attribute memberOf = srLdapUser.getAttributes().get("memberOf");
        if (memberOf != null) 
        { // null if this user belongs to no group at all
            for (int i = 0; i < memberOf.size(); i++) 
            {
                Attributes atts = ctx.getAttributes(memberOf.get(i).toString(), new String[] { "CN" });
                Attribute att = atts.get("CN");
                if(att!=null) 
                	groups.add(att.get().toString());
            }
        }
        return groups.toArray(new String[groups.size()]);
	}

	/**
	 * The binary data is in the form: byte[0] - revision level byte[1] - count
	 * of sub-authorities byte[2-7] - 48 bit authority (big-endian) and then
	 * count x 32 bit sub authorities (little-endian)
	 * 
	 * The String value is: S-Revision-Authority-SubAuthority[n]...
	 * 
	 * Based on code from here -
	 * http://forums.oracle.com/forums/thread.jspa?threadID=1155740&tstart=0
	 */
	public static String decodeSID(byte[] sid) {

		final StringBuilder strSid = new StringBuilder("S-");

		// get version
		final int revision = sid[0];
		strSid.append(Integer.toString(revision));

		// next byte is the count of sub-authorities
		final int countSubAuths = sid[1] & 0xFF;

		// get the authority
		long authority = 0;
		// String rid = "";
		for (int i = 2; i <= 7; i++) {
			authority |= ((long) sid[i]) << (8 * (5 - (i - 2)));
		}
		strSid.append("-");
		strSid.append(Long.toHexString(authority));

		// iterate all the sub-auths
		int offset = 8;
		int size = 4; // 4 bytes for each sub auth
		for (int j = 0; j < countSubAuths; j++) {
			long subAuthority = 0;
			for (int k = 0; k < size; k++) {
				subAuthority |= (long) (sid[offset + k] & 0xFF) << (8 * k);
			}

			strSid.append("-");
			strSid.append(subAuthority);

			offset += size;
		}

		return strSid.toString();
	}
}
