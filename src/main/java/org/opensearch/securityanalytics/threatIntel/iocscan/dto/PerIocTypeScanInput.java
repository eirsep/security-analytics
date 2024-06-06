package org.opensearch.securityanalytics.threatIntel.iocscan.dto;

import org.opensearch.commons.alerting.model.Input;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DTO that contains information about an Ioc type, the indices storing iocs of that ioc type and
 * list of fields in each index that contain values of the given ioc type like Ip addresss contain fields.
 * List of indices is optional. If indices is empty we scan the feed config and get the list of indices
 */
public class PerIocTypeScanInput implements Writeable, ToXContentObject, Input {

    private static final String IOC_TYPE = "ioc_type";
    private static final String INDEX_TO_FIELDS_MAP = "index_to_fields_map";
    private static final String INDICES = "indices";
    private final String iocType;
    private final Map<String, List<String>> indexToFieldsMap;
    private final List<String> indices;

    public PerIocTypeScanInput(String iocType, Map<String, List<String>> indexToFieldsMap, List<String> indices) {
        this.iocType = iocType;
        this.indexToFieldsMap = indexToFieldsMap;
        this.indices = indices;
    }

    public PerIocTypeScanInput(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readMapOfLists(StreamInput::readString, StreamInput::readString),
                sin.readStringList()
        );
    }

    public String getIocType() {
        return iocType;
    }

    public Map<String, List<String>> getIndexToFieldsMap() {
        return indexToFieldsMap;
    }

    public List<String> getIndices() {
        return indices;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(iocType);
        out.writeMapOfLists(indexToFieldsMap, StreamOutput::writeString, StreamOutput::writeString);
        out.writeStringCollection(indices);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(IOC_TYPE, iocType)
                .field(INDEX_TO_FIELDS_MAP, indexToFieldsMap)
                .field(INDICES, indices)
                .endObject();
    }

    public static PerIocTypeScanInput parse(XContentParser xcp) throws IOException {
        String iocType = null;
        Map<String, List<String>> indexToFieldsMap = new HashMap<>();
        List<String> indices = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case IOC_TYPE:
                    iocType = xcp.text();
                    break;
                case INDEX_TO_FIELDS_MAP:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        indexToFieldsMap = null;
                    } else {
                        indexToFieldsMap = xcp.map(HashMap::new, p -> {
                            List<String> fields = new ArrayList<>();
                            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                            while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                                fields.add(xcp.text());
                            }
                            return fields;
                        });
                    }
                    break;
                case INDICES:
                    List<String> strings = new ArrayList<>();
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        strings.add(xcp.text());
                    }
                    indices = strings;
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new PerIocTypeScanInput(iocType, indexToFieldsMap, indices);
    }

    @Override
    public String name() {
        return ThreatIntelMonitorDto.PER_IOC_TYPE_SCAN_INPUT_FIELD;
    }
}