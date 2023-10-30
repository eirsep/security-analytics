/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.feedMetadata;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;
import org.opensearch.securityanalytics.util.FileUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class BuiltInTIFMetadataLoader extends AbstractLifecycleComponent {

    private static final Logger logger = LogManager.getLogger(BuiltInTIFMetadataLoader.class);

    private static final String BASE_PATH = "threatIntelFeed/";


    private List<TIFMetadata> tifMetadataList = null;
    private Map<String, TIFMetadata> tifMetadataByName;

    public List<TIFMetadata> getTifMetadataList() {
        ensureTifMetadataLoaded();
        return tifMetadataList;
    }

    public TIFMetadata getTifMetadataByName(String name) {
        ensureTifMetadataLoaded();
        return tifMetadataByName.get(name);
    }

    public boolean tifMetadataExists(String name) {
        ensureTifMetadataLoaded();
        return tifMetadataByName.containsKey(name);
    }

    public void ensureTifMetadataLoaded() {
        try {
            if (tifMetadataList != null) {
                return;
            }
            loadBuiltInTifMetadata();
            tifMetadataByName = tifMetadataList.stream()
                    .collect(Collectors.toMap(TIFMetadata::getName, Function.identity()));
        } catch (Exception e) {
            logger.error("Failed loading builtin log types from disk!", e);
        }
    }

    @SuppressWarnings("unchecked")
    protected void loadBuiltInTifMetadata() throws URISyntaxException, IOException {
        final String url = Objects.requireNonNull(BuiltInTIFMetadataLoader.class.getClassLoader().getResource(BASE_PATH),
                "Built-in threat intel feed metadata file not found").toURI().toString();
        Path dirPath = null;
        if (url.contains("!")) {
            final String[] paths = url.split("!");
            dirPath = FileUtils.getFs().getPath(paths[1]);
        } else {
            dirPath = Path.of(url);
        }

        Stream<Path> folder = Files.list(dirPath);
        Path tifMetadataPath = folder.filter(e -> e.toString().endsWith("feedMetadata.json")).collect(Collectors.toList()).get(0);
        try (
                InputStream is = BuiltInTIFMetadataLoader.class.getResourceAsStream(tifMetadataPath.toString())
        ) {
            String tifMetadataFilePayload = new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);

            if (tifMetadataFilePayload != null) {
                if (tifMetadataList == null)
                    tifMetadataList = new ArrayList<>();
                Map<String, Object> tifMetadataFileAsMap =
                        XContentHelper.convertToMap(JsonXContent.jsonXContent, tifMetadataFilePayload, false);

                for (Map.Entry<String, Object> mapEntry : tifMetadataFileAsMap.entrySet()) {
                    Map<String, Object> tifMetadataMap = (Map<String, Object>) mapEntry.getValue();
                    tifMetadataList.add(new TIFMetadata(tifMetadataMap));
                }
            }
        } catch (Exception e) {
            throw new SettingsException("Failed to load builtin threat intel feed metadata" +
                    "", e);
        }
        Stream<Path> folder1 = Files.list(dirPath);
        Path jsonlPath = folder1.filter(e -> e.toString().endsWith("a.jsonl")).collect(Collectors.toList()).get(0);
        try {
            BufferedReader br = Files.newBufferedReader(jsonlPath);
            try {
                String line;
                JsonFactory factory = new JsonFactory();
                ObjectMapper objectMapper = new ObjectMapper();
                while ((line = br.readLine()) != null) {
                    JsonParser parser = factory.createParser(line);
                    JsonNode jsonNode = objectMapper.readTree(parser);

                    if (jsonNode.has("object") && jsonNode.has("disposition")) {
                        String value = jsonNode.get("object").asText();
                        String disposition = jsonNode.get("disposition").asText();
                         System.out.println(String.format("SASHANKvalue:%s, disposition:%s", value, disposition));
                        logger.error(String.format("SASHANKvalue:%s, disposition:%s", value, disposition));
                    }
                }
            } finally {
                br.close();
            }
        } catch (Exception e) {
            logger.error(e);
        }
    }

    @Override
    protected void doStart() {
        ensureTifMetadataLoaded();
    }

    @Override
    protected void doStop() {

    }

    @Override
    protected void doClose() throws IOException {

    }
}
