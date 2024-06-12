package org.opensearch.securityanalytics.threatIntel.model.monitor;


import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.DocLevelMonitorInput;
import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.ScheduledJob;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteDocLevelMonitorInput;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;

public class ThreatIntelInputTests extends OpenSearchTestCase {

    public void testThreatInputSerde() throws IOException {
        ThreatIntelInput threatIntelInput = getThreatIntelInput();
        BytesStreamOutput out = new BytesStreamOutput();
        threatIntelInput.writeTo(out);
        BytesReference bytes = out.bytes();
        RemoteDocLevelMonitorInput remoteDocLevelMonitorInput = new RemoteDocLevelMonitorInput(
                bytes,
                new DocLevelMonitorInput("threat intel input",
                        List.of("index1", "index2"),
                        emptyList()
                )
        );
        Monitor monitor = new Monitor(
                Monitor.NO_ID,
                Monitor.NO_VERSION,
                randomAlphaOfLength(10),
                true,
                new IntervalSchedule(1, ChronoUnit.MINUTES, null),
                Instant.now(),
                Instant.now(),
                "remote_doc_level_monitor",
                null,
                4,
                List.of(
                        remoteDocLevelMonitorInput
                ),
                emptyList(),
                emptyMap(),
                new DataSources(),
                "security_analytics"
        );
        BytesStreamOutput monitorOut = new BytesStreamOutput();
        monitor.writeTo(monitorOut);

        String monitorString = BytesReference.bytes(monitor.toXContentWithUser(jsonBuilder(), ToXContent.EMPTY_PARAMS)).utf8ToString();
        Monitor parsedMonitor = Monitor.parse(getParser(monitorString), Monitor.NO_ID, Monitor.NO_VERSION);
        assertEquals(((RemoteDocLevelMonitorInput) parsedMonitor.getInputs().get(0)).getInput(), ((RemoteDocLevelMonitorInput) parsedMonitor.getInputs().get(0)).getInput());
    }

    private ThreatIntelInput getThreatIntelInput() {
        return new ThreatIntelInput(randomList(randomInt(5), () -> randomPerIocTypeThreatIntel()));
    }

    private PerIocTypeScanInput randomPerIocTypeThreatIntel() {
        return new PerIocTypeScanInput(
                randomAlphaOfLength(10),
                Map.of("index1", List.of("f1", "f2"), "index2", List.of("f3", "f4"))
        );
    }

    public XContentParser getParser(String xc) throws IOException {
        XContentParser parser = XContentType.JSON.xContent().createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, xc);
        parser.nextToken();
        return parser;

    }

    public String toJsonString(Monitor monitor) throws IOException {
        XContentBuilder builder = jsonBuilder();
        return monitor.toXContent(builder, ToXContent.EMPTY_PARAMS).toString();

    }
}