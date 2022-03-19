package com.swashtech.utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.bazaarvoice.jolt.Chainr;
import com.bazaarvoice.jolt.JsonUtils;

@Service
public class JSchemaUtility {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	public JSONObject validateSchema(JSONObject jsonSchema, JSONObject inputRequest) {
		JSONObject response = new JSONObject();
		try {
			Schema schema = SchemaLoader.load(jsonSchema);
			schema.validate(inputRequest);
			response.put("status", "Success");
			response.put("message", "Schema Validated");
		} catch (ValidationException e) {
			response.put("status", "Error");
			response.put("message", e.getAllMessages());
		}
		return response;
	}

	public JSONObject transformJolt(JSONArray jsonSchema, JSONObject inputRequest) {
		JSONObject response = new JSONObject();
		try {
			List<?> chainrConfig = JsonUtils.jsonToList(jsonSchema.toString());
			Chainr chainr = Chainr.fromSpec(chainrConfig);
			Object input = JsonUtils.jsonToObject(inputRequest.toString());
			Object jsonOutput = chainr.transform(input);
			response.put("status", "Success");
			response.put("response", jsonOutput);

		} catch (Exception e) {
			response.put("status", "Error");
			response.put("message", e.getMessage());

		}
		return response;
	}

	public JSONObject readResourceFile(String fileName) {
		JSONObject jsonObject = null;
		ClassLoader classLoader = getClass().getClassLoader();
		try (InputStream inputStream = classLoader.getResourceAsStream(fileName)) {
			String result = IOUtils.toString(inputStream, StandardCharsets.UTF_8);
			logger.debug("readResourceFile() : result : " + result);
			jsonObject = new JSONObject(result);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return jsonObject;
	}

}
