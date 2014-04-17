package demo;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = Application.class)
@WebAppConfiguration
@IntegrationTest
public class ApplicationTests {

	@Test
	public void contextLoads() {
		TestRestTemplate template = new TestRestTemplate();
		ResponseEntity<String> response = template.getForEntity("http://localhost:8080/api/", String.class);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
	}

}
