package hello;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

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



@RestController
public class AccountController {
	static String ldapAdServer = "ldap://ad.internal.satoglobalsolutions.com:389";
	static String ldapSearchBase = "DC=apps-sgs,DC=com";
	static String ldapUsername = "corali";
	static String ldapPassword = "Welcome123";
	static String LdapCtxFactory = "com.sun.jndi.ldap.LdapCtxFactory";
	
	@CrossOrigin(origins = "*")
	@RequestMapping(value = "/authenticateUser", method = {RequestMethod.POST, RequestMethod.OPTIONS }, produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
	public @ResponseBody UserDTO authenticate(@RequestBody AutenticateDTO credentials)  {	
		Hashtable<String, Object> env = new Hashtable<String, Object>();
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
		env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
		env.put(Context.INITIAL_CONTEXT_FACTORY, LdapCtxFactory);
		env.put(Context.PROVIDER_URL, ldapAdServer);
		
		// ensures that objectSID attribute values will be returned as a byte[] instead of a String
		env.put("java.naming.ldap.attributes.binary", "objectSID");
		// the following is helpful in debugging errors
		env.put("com.sun.jndi.ldap.trace.ber", System.err);
		
		UserDTO user = new UserDTO();
		try {
			
			DirContext authContext = new InitialDirContext(env);
			AccountController ldap = new AccountController();

			SearchResult srLdapUser = ldap.findAccountByUserNameAndPassword(authContext, ldapSearchBase, credentials);
			if(srLdapUser!=null){
			Attributes attr = srLdapUser.getAttributes();
			user.setName((String) attr.get("displayname").get());
			if(attr.get("mail") != null && attr.get("mail").get(0) != null)
			        user.setEmail((String) attr.get("mail").get(0).toString());
			else user.setEmail(""); 
			user.setUserName((String) attr.get("sAMAccountName").get());
			user.setGroups(ldap.getUserGroups(authContext, srLdapUser));
			//user.setRole(getUserOU(authContext, srLdapUser)[1]);
			}
			return user;
			
		} catch (AuthenticationException ex) {
			ex.printStackTrace();
		} catch (NamingException ex) {
			ex.printStackTrace();
		}
		return new UserDTO();
	}

	public SearchResult findAccountByUserNameAndPassword(DirContext ctx, String ldapSearchBase, AutenticateDTO account) {
		String searchFilter = "(&(objectClass=user)(sAMAccountName=" + account.getUser() + "))";
		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		try {
			NamingEnumeration<SearchResult> results = ctx.search(ldapSearchBase, searchFilter, searchControls);
			SearchResult searchResult = null;
			if (results.hasMoreElements()) {
				
				searchResult = (SearchResult) results.nextElement();
				String distinguishedName = searchResult.getNameInNamespace();
				Properties authEnv = new Properties();
	
				authEnv.put(Context.INITIAL_CONTEXT_FACTORY, LdapCtxFactory);
				authEnv.put(Context.PROVIDER_URL, ldapAdServer);
				
				authEnv.put(Context.SECURITY_PRINCIPAL, distinguishedName);
				authEnv.put(Context.SECURITY_CREDENTIALS, account.getPass());
				new InitialDirContext(authEnv);

				System.out.println("Authentication successful");
				return searchResult;
			}
			return null;
		} 
		catch (NamingException ex) {
			ex.printStackTrace();
		}
		return null;
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

	public String[] getUserGroups(DirContext ctx,SearchResult srLdapUser) {
		try{
		List<String> groups = new ArrayList<String>();
		//if(srLdapUser.getAttributes().get("memberOf") != null && srLdapUser.getAttributes().get("memberOf").get(0) != null){
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
		}catch (NamingException ex) {
			ex.printStackTrace();
		}
		return null;
	}

	// @RequestMapping(value ="/authenticate", method = RequestMethod.GET)
//		@RequestMapping(value = "/authenticate", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
//		public UserDTO authenticate(@RequestParam(name = "user", defaultValue = "user") String user, @RequestParam(name = "password", defaultValue = "password") String pass) {
//			String username = "corali";
//			String password = "Welcome123";
//			String base = "DC=apps-sgs,DC=com";
//			String dn = "uid=" + username + "," + base;
//			String ldapURL = "ldap://ad.internal.satoglobalsolutions.com:389/DC=apps-sgs,DC=com";
//
//			// Setup environment for authenticating
//
//			Hashtable<String, String> environment = new Hashtable<String, String>();
//			environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
//			environment.put(Context.PROVIDER_URL, ldapURL);
//			environment.put(Context.SECURITY_AUTHENTICATION, "simple");
//			environment.put(Context.SECURITY_PRINCIPAL, username);
//			environment.put(Context.SECURITY_CREDENTIALS, password);
//			//environment.put(Context.SECURITY_PROTOCOL, "ssl");
//			
////			Hashtable env = new Hashtable();
////			env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
////			env.put(Context.PROVIDER_URL, ldapURL);
//	//
////			// Use anonymous authentication
////			env.put(Context.SECURITY_AUTHENTICATION, "none");
//
//			// Create the initial context
//			
//			try {
//				//DirContext ctx = new InitialDirContext(env);
//				DirContext authContext = new InitialDirContext(environment);
//				//return new UserDTO("javi", "ADMIN", "Javier Barriere");
//			
//			}catch (AuthenticationException ex) {
//				ex.printStackTrace();
//			} catch (NamingException ex) {
//				ex.printStackTrace();
//			}
//			return new UserDTO();
//			
//		}
//

}
