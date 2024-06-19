package org.opensearch.securityanalytics.threatIntel.iocscan.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.client.Client;
import org.opensearch.common.document.DocumentField;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.threatIntel.iocscan.model.Ioc;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

public class SaIoCScanService extends IoCScanService<SearchHit> {

    private static final Logger log = LogManager.getLogger(SaIoCScanService.class);
    private final Client client;
    private final NamedXContentRegistry xContentRegistry;

    public SaIoCScanService(Client client) {
        this.client = client;
    }

    @Override
    void matchAgainstThreatIntelAndReturnMaliciousIocs(
            Map<String, Set<String>> iocPerTypeSet,
            Monitor monitor,
            BiConsumer<List<Ioc>, Exception> callback,
            Map<String, List<String>> iocTypeToIndices) {
        long startTime = System.currentTimeMillis();
        for (String iocType : iocPerTypeSet.keySet()) {
            GroupedActionListener<List<SearchHit>> perIocTypeListener = new GroupedActionListener<>(
                    new ActionListener<Collection<List<SearchHit>>>() {
                        @Override
                        public void onResponse(Collection<List<SearchHit>> lists) {
                            List<SearchHit> hits = new ArrayList<>();
                            lists.forEach(hits::addAll);
                            List<Ioc> ioc = new ArrayList<>();
                            hits.forEach();
                        }

                        @Override
                        public void onFailure(Exception e) {

                        }
                    },
                    iocPerTypeSet.size()
            )
            if(iocTypeToIndices.containsKey(iocType)) {

            } else {
                perIocTypeListener
            }
        }
        callback.accept(Collections.emptyList(), null);
    }

    @Override
    public List<String> getValuesAsStringList(SearchHit hit, String field) {
        if (hit.getFields().containsKey(field)) {
            DocumentField documentField = hit.getFields().get(field);
            return documentField.getValues().stream().filter(Objects::nonNull).map(Object::toString).collect(Collectors.toList());
        } else return Collections.emptyList();
    }

    @Override
    public String getIndexName(SearchHit hit) {
        return hit.getIndex();
    }

    @Override
    public String getId(SearchHit hit) {
        return hit.getId();
    }

    @Override
    void saveIocs(List<Ioc> iocs, BiConsumer<List<Ioc>, Exception> callback) {
        callback.accept(Collections.emptyList(), null);
    }
}
