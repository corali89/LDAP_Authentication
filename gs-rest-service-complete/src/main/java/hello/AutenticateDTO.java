package hello;

public class AutenticateDTO {
	private String user;
	private String pass;
	
	
	public AutenticateDTO() {
		super();
		// TODO Auto-generated constructor stub
	}
	public AutenticateDTO(String user, String pass) {
		super();
		this.user = user;
		this.pass = pass;
	}
	public String getUser() {
		return user;
	}
	public void setUser(String user) {
		this.user = user;
	}
	public String getPass() {
		return pass;
	}
	public void setPass(String pass) {
		this.pass = pass;
	}
	
}
