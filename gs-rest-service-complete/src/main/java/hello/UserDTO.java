package hello;


public class UserDTO {
	private String userName;
	private String role;
	private String name;
	private String[] groups;
	private String email;
	
	
	public UserDTO(String userName, String role, String name, String[] groups, String email) {
		super();
		this.userName = userName;
		this.role = role;
		this.name = name;
		this.groups = groups;
		this.email = email;
	}
	
	public UserDTO() {		
	}

	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
	public String getRole() {
		return role;
	}
	public void setRole(String role) {
		this.role = role;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String[] getGroups() {
		return groups;
	}
	public void setGroups(String[] groups) {
		this.groups = groups;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
		
}
