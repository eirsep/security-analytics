package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.threatIntel.common.RefreshType;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.PerIocTypeScanInputDto;
import org.opensearch.securityanalytics.threatIntel.model.DefaultIocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
import static org.opensearch.securityanalytics.threatIntel.resthandler.monitor.RestSearchThreatIntelMonitorAction.SEARCH_THREAT_INTEL_MONITOR_PATH;

public class ThreatIntelMonitorRestApiIT extends SecurityAnalyticsRestTestCase {
    private static final Logger log = LogManager.getLogger(ThreatIntelMonitorRestApiIT.class);

    public void indexSourceConfigsAndIocs(int num, List<String> iocVals) throws IOException {
        for (int i = 0; i < num; i++) {
            String configId = "id" + i;
            String iocIndexName = ".opensearch-sap-ioc-" + configId;
            indexTifSourceConfig(num, configId, iocIndexName, i);
            for (int i1 = 0; i1 < iocVals.size(); i1++) {
                indexIocs(iocVals, iocIndexName, i1, configId);
            }
        }
    }

    private void indexIocs(List<String> iocVals, String iocIndexName, int i1, String configId) throws IOException {
        String iocId = iocIndexName + i1;
        STIX2IOC stix2IOC = new STIX2IOC(
                iocId,
                "random",
                IOCType.ip,
                iocVals.get(i1),
                "",
                Instant.now(),
                Instant.now(),
                "",
                Collections.emptyList(),
                configId,
                "",
                STIX2IOC.NO_VERSION
        );
        indexDoc(iocIndexName, iocId, stix2IOC.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS).toString());
        List<SearchHit> searchHits = executeSearch(iocIndexName, getMatchAllSearchRequestString(iocVals.size()));
        assertEquals(searchHits.size(), i1 + 1);
    }

    private void indexTifSourceConfig(int num, String configId, String iocIndexName, int i) throws IOException {
        SATIFSourceConfig config = new SATIFSourceConfig(
                configId,
                SATIFSourceConfig.NO_VERSION,
                "name1",
                "STIX2",
                SourceConfigType.S3_CUSTOM,
                "description",
                "createdByUser",
                Instant.now(),
                new S3Source("bucketname", "key", "region", "roleArn"),
                null,
                Instant.now(),
                new org.opensearch.jobscheduler.spi.schedule.IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES),
                TIFJobState.AVAILABLE,
                RefreshType.FULL,
                null,
                null,
                false,
                new DefaultIocStoreConfig(Map.of("ip", List.of(iocIndexName))),
                List.of("ip")
        );
        String indexName = SecurityAnalyticsPlugin.JOB_INDEX_NAME;
        Response response = indexDoc(indexName, configId, config.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS).toString());
    }

    public void testCreateThreatIntelMonitor() throws IOException {
        List<String> vals = List.of("ip1", "ip2");
        indexSourceConfigsAndIocs(1, vals);
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        String monitorName = "test_monitor_name";

        ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto(index);
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        final String monitorId = responseBody.get("id").toString();
        Assert.assertNotEquals("response is missing Id", Monitor.NO_ID, monitorId);

        Response alertingMonitorResponse = getAlertingMonitor(client(), monitorId);
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        int i = 1;
        for (String val : vals) {
            String doc = String.format("{\"ip\":\"%s\", \"ip1\":\"%s\"}", val, val);
            try {
                indexDoc(index, "" + i++, doc);
            } catch (IOException e) {
                fail();
            }
        }

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        assertEquals(1, 1);

        String matchAllRequest = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        Response searchMonitorResponse = makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON, false));
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        HashMap<String, Object> hits = (HashMap<String, Object>) asMap(searchMonitorResponse).get("hits");
        HashMap<String, Object> totalHits = (HashMap<String, Object>) hits.get("total");
        Integer totalHitsVal = (Integer) totalHits.get("value");
        assertEquals(totalHitsVal.intValue(), 1);
        makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON, false));

        Response delete = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI + "/" + monitorId, Collections.emptyMap(), null);
        Assert.assertEquals(200, delete.getStatusLine().getStatusCode());

        searchMonitorResponse = makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON, false));
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        hits = (HashMap<String, Object>) asMap(searchMonitorResponse).get("hits");
        totalHits = (HashMap<String, Object>) hits.get("total");
        totalHitsVal = (Integer) totalHits.get("value");
        assertEquals(totalHitsVal.intValue(), 0);
        Response iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        Map<String, Object> responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(2, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());
    }

    private ThreatIntelMonitorDto randomIocScanMonitorDto(String index) {
        return new ThreatIntelMonitorDto(
                Monitor.NO_ID,
                randomAlphaOfLength(10),
                List.of(new PerIocTypeScanInputDto("IP", Map.of(index, List.of("ip")))),
                new IntervalSchedule(1, ChronoUnit.MINUTES, Instant.now()),
                false, //todo change to true after testing
                null,
                List.of(index), Collections.emptyList());
    }
}

