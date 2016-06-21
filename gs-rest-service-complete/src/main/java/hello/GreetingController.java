package hello;

import java.util.concurrent.atomic.AtomicLong;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class GreetingController {

    private static final String template = "Hello, %s!";
    private final AtomicLong counter = new AtomicLong();

    @RequestMapping("/greeting")
    public Greeting greeting(@RequestParam(value="name", defaultValue="World") String name) {
        return new Greeting(counter.incrementAndGet(),
                            String.format(template, name));
    }
    
//    @RequestMapping(value ="/autenticate", method = RequestMethod.POST, produces= MediaType.APPLICATION_JSON_VALUE, consumes= MediaType.APPLICATION_JSON_VALUE)
//    public @ResponseBody UserDTO autentica(@RequestParam(name="user" , defaultValue="user") String user, @RequestParam(name="password", defaultValue="password") String password){
//    	return new UserDTO("ctriana","ADMIN","Colali TRiana");
//    }
    
//    @RequestMapping(value ="/autenticate2", method = RequestMethod.POST, produces= MediaType.APPLICATION_JSON_VALUE, consumes= MediaType.APPLICATION_JSON_VALUE)
//    public @ResponseBody UserDTO autentica2(@RequestBody AutenticateDTO aut) {
//    	return new UserDTO(aut.getUser(),"ADMIN", "Nico");
//    }
}
