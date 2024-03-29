package com.swashtech.config;

import static com.google.common.base.Predicates.or;
import static springfox.documentation.builders.PathSelectors.regex;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.google.common.base.Predicate;

import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig {

	@Bean
	public Docket postsApi() {
		return new Docket(DocumentationType.SWAGGER_2).groupName("authorization-api").apiInfo(apiInfo()).select()
				.paths(postPaths()).build();
	}

	private Predicate<String> postPaths() {
		return or(regex("/api/posts.*"), regex("/api.*"));
	}

	private ApiInfo apiInfo() {
		// http://localhost:8090/swashtech-api/v2/api-docs?group=swashtech-api
		return new ApiInfoBuilder().title("Rush Management Service").description("OAuth Authorization Server API's")
				.termsOfServiceUrl("http://www.ashishsirsikar.com").contact("Ashish Sirsikar")
				.license("SwashTech Licensed").licenseUrl("http://www.ashishsirsikar.com").version("TM").build();
	}

}