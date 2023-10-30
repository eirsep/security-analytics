/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.securityanalytics.threatIntel.common.Constants;
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.AccessController;
import java.security.PrivilegedAction;

//Parser helper class
public class ThreatIntelFeedParser {
    private static final Logger log = LogManager.getLogger(ThreatIntelFeedParser.class);

    /**
     * Create CSVParser of a threat intel feed
     *
     * @param tifMetadata Threat intel feed metadata
     * @return parser for threat intel feed
     */
    @SuppressForbidden(reason = "Need to connect to http endpoint to read threat intel feed database file")
    public static CSVParser getThreatIntelFeedReaderCSV(final TIFMetadata tifMetadata) {
        SpecialPermission.check();
        return AccessController.doPrivileged((PrivilegedAction<CSVParser>) () -> {
            try {
                URL url = new URL(tifMetadata.getUrl());
                URLConnection connection = url.openConnection();
                connection.addRequestProperty(Constants.USER_AGENT_KEY, Constants.USER_AGENT_VALUE);
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                return new CSVParser(reader, CSVFormat.RFC4180);
            } catch (IOException e) {
                log.error("Exception: failed to read threat intel feed data from {}", tifMetadata.getUrl(), e);
                throw new OpenSearchException("failed to read threat intel feed data from {}", tifMetadata.getUrl(), e);
            }
        });
    }

    public static void main(String[] args) throws IOException {
       
    }
}
