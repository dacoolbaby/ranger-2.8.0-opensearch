/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ranger.audit.destination;

import java.io.File;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.thirdparty.com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.ranger.audit.model.AuditEventBase;
import org.apache.ranger.audit.model.AuthzAuditEvent;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.authorization.credutils.CredentialsProviderUtil;
import org.apache.ranger.authorization.credutils.kerberos.KerberosCredentialsProvider;
import org.opensearch.action.admin.indices.open.OpenIndexRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.common.xcontent.XContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;

/**
 * OpenSearch implementation of AuditDestination.
 *
 * This class provides backward compatibility with Elasticsearch configuration keys.
 * Configuration property key resolution order:
 * 1. ranger.audit.opensearch.* (new preferred prefix)
 * 2. ranger.audit.elasticsearch.* (legacy prefix for backward compatibility)
 *
 * Similarly for plugin-side configuration:
 * 1. xasecure.audit.destination.opensearch.* (new preferred prefix)
 * 2. xasecure.audit.destination.elasticsearch.* (legacy prefix for backward compatibility)
 */
public class OpenSearchAuditDestination extends AuditDestination {
    private static final Logger LOG = LoggerFactory.getLogger(OpenSearchAuditDestination.class);

    private static final ThreadLocal<DateFormat> DATE_FORMAT = ThreadLocal.withInitial(() -> {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format;
    });

    // Configuration key names
    public static final String CONFIG_URLS     = "urls";
    public static final String CONFIG_PORT     = "port";
    public static final String CONFIG_USER     = "user";
    public static final String CONFIG_PASSWORD = "password";
    public static final String CONFIG_PROTOCOL = "protocol";
    public static final String CONFIG_INDEX    = "index";

    // Configuration prefixes - new OpenSearch prefix (preferred)
    public static final String CONFIG_PREFIX_OPENSEARCH         = "ranger.audit.opensearch";
    public static final String CONFIG_PREFIX_OPENSEARCH_PLUGIN  = "xasecure.audit.destination.opensearch";

    // Configuration prefixes - legacy Elasticsearch prefix (for backward compatibility)
    public static final String CONFIG_PREFIX_ELASTICSEARCH         = "ranger.audit.elasticsearch";
    public static final String CONFIG_PREFIX_ELASTICSEARCH_PLUGIN  = "xasecure.audit.destination.elasticsearch";

    public static final String DEFAULT_INDEX = "ranger_audits";

    private String index = DEFAULT_INDEX;
    private final AtomicReference<RestHighLevelClient> clientRef = new AtomicReference<>(null);
    private String protocol;
    private String user;
    private int port;
    private String password;
    private String hosts;
    private Subject subject;
    private boolean usingLegacyConfig = false;

    public OpenSearchAuditDestination() {
        propPrefix = CONFIG_PREFIX_OPENSEARCH;
    }

    @Override
    public void init(Properties props, String propPrefix) {
        super.init(props, propPrefix);

        // Determine effective prefix with fallback support
        String effectivePrefix = determineEffectivePrefix(props, propPrefix);

        this.protocol = getStringPropertyWithFallback(props, effectivePrefix, CONFIG_PROTOCOL, "http");
        this.user = getStringPropertyWithFallback(props, effectivePrefix, CONFIG_USER, "");
        this.password = getStringPropertyWithFallback(props, effectivePrefix, CONFIG_PASSWORD, "");
        this.port = getIntPropertyWithFallback(props, effectivePrefix, CONFIG_PORT, 9200);
        this.index = getStringPropertyWithFallback(props, effectivePrefix, CONFIG_INDEX, DEFAULT_INDEX);
        this.hosts = getHosts(props, effectivePrefix);

        if (usingLegacyConfig) {
            LOG.info("Using legacy Elasticsearch configuration keys. Consider migrating to opensearch.* prefix for better clarity.");
        }

        LOG.info("Connecting to OpenSearch: {}", connectionString());
        getClient(); // Initialize client
    }

    /**
     * Determine the effective configuration prefix with fallback support.
     * Priority: opensearch.* > elasticsearch.*
     */
    private String determineEffectivePrefix(Properties props, String providedPrefix) {
        // If the provided prefix is for opensearch, use it
        if (providedPrefix != null && providedPrefix.contains("opensearch")) {
            return providedPrefix;
        }

        // Check if opensearch.* configuration exists
        String opensearchPrefix = providedPrefix != null && providedPrefix.startsWith("xasecure")
                ? CONFIG_PREFIX_OPENSEARCH_PLUGIN
                : CONFIG_PREFIX_OPENSEARCH;

        String legacyPrefix = providedPrefix != null && providedPrefix.startsWith("xasecure")
                ? CONFIG_PREFIX_ELASTICSEARCH_PLUGIN
                : CONFIG_PREFIX_ELASTICSEARCH;

        // Check if any opensearch.* keys exist
        boolean hasOpenSearchConfig = hasAnyConfigWithPrefix(props, opensearchPrefix);

        if (hasOpenSearchConfig) {
            return opensearchPrefix;
        }

        // Fallback to elasticsearch.* prefix
        usingLegacyConfig = true;
        return legacyPrefix;
    }

    /**
     * Check if any configuration key exists with the given prefix.
     */
    private boolean hasAnyConfigWithPrefix(Properties props, String prefix) {
        for (Object key : props.keySet()) {
            String keyStr = key.toString();
            if (keyStr.startsWith(prefix + ".")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get string property with fallback from opensearch.* to elasticsearch.* prefix.
     */
    private String getStringPropertyWithFallback(Properties props, String effectivePrefix, String configKey, String defaultValue) {
        // First try the effective prefix
        String value = MiscUtil.getStringProperty(props, effectivePrefix + "." + configKey);
        if (value != null) {
            return value;
        }

        // If using opensearch prefix, try fallback to elasticsearch prefix
        if (effectivePrefix.contains("opensearch")) {
            String fallbackPrefix = effectivePrefix.replace("opensearch", "elasticsearch");
            value = MiscUtil.getStringProperty(props, fallbackPrefix + "." + configKey);
            if (value != null) {
                LOG.debug("Using fallback configuration key: {}", fallbackPrefix + "." + configKey);
                return value;
            }
        }

        return defaultValue;
    }

    /**
     * Get integer property with fallback from opensearch.* to elasticsearch.* prefix.
     */
    private int getIntPropertyWithFallback(Properties props, String effectivePrefix, String configKey, int defaultValue) {
        // First try the effective prefix
        String key = effectivePrefix + "." + configKey;
        String valueStr = props.getProperty(key);
        if (valueStr != null && !valueStr.trim().isEmpty()) {
            try {
                return Integer.parseInt(valueStr.trim());
            } catch (NumberFormatException e) {
                LOG.warn("Invalid integer value for property {}: {}", key, valueStr);
            }
        }

        // If using opensearch prefix, try fallback to elasticsearch prefix
        if (effectivePrefix.contains("opensearch")) {
            String fallbackPrefix = effectivePrefix.replace("opensearch", "elasticsearch");
            String fallbackKey = fallbackPrefix + "." + configKey;
            valueStr = props.getProperty(fallbackKey);
            if (valueStr != null && !valueStr.trim().isEmpty()) {
                try {
                    int value = Integer.parseInt(valueStr.trim());
                    LOG.debug("Using fallback configuration key: {}", fallbackKey);
                    return value;
                } catch (NumberFormatException e) {
                    LOG.warn("Invalid integer value for property {}: {}", fallbackKey, valueStr);
                }
            }
        }

        return defaultValue;
    }

    private String connectionString() {
        return String.format(Locale.ROOT, "User:%s, %s://%s:%s/%s", user, protocol, hosts, port, index);
    }

    @Override
    public void stop() {
        super.stop();
        logStatus();
        closeClient();
    }

    /**
     * Close the OpenSearch client gracefully.
     */
    private void closeClient() {
        RestHighLevelClient client = clientRef.getAndSet(null);
        if (client != null) {
            try {
                client.close();
                LOG.info("OpenSearch client closed successfully");
            } catch (IOException e) {
                LOG.warn("Error closing OpenSearch client: {}", e.getMessage(), e);
            }
        }
    }

    @Override
    public boolean log(Collection<AuditEventBase> events) {
        boolean ret = false;
        try {
            logStatusIfRequired();
            addTotalCount(events.size());

            RestHighLevelClient client = getClient();
            if (null == client) {
                // OpenSearch is still not initialized. So need return error
                addDeferredCount(events.size());
                return ret;
            }

            ArrayList<AuditEventBase> eventList = new ArrayList<>(events);
            BulkRequest bulkRequest = new BulkRequest();
            try {
                eventList.forEach(event -> {
                    AuthzAuditEvent authzEvent = (AuthzAuditEvent) event;
                    String id = authzEvent.getEventId();
                    Map<String, Object> doc = toDoc(authzEvent);
                    bulkRequest.add(new IndexRequest(index).id(id).source(doc, XContentType.JSON));
                });
            } catch (Exception ex) {
                addFailedCount(eventList.size());
                logFailedEvent(eventList, ex);
            }
            BulkResponse response = client.bulk(bulkRequest, RequestOptions.DEFAULT);
            if (response.status().getStatus() >= 400) {
                addFailedCount(eventList.size());
                logFailedEvent(eventList, "HTTP " + response.status().getStatus());
            } else {
                BulkItemResponse[] items = response.getItems();
                for (int i = 0; i < items.length; i++) {
                    AuditEventBase itemRequest = eventList.get(i);
                    BulkItemResponse itemResponse = items[i];
                    if (itemResponse.isFailed()) {
                        addFailedCount(1);
                        logFailedEvent(Arrays.asList(itemRequest), itemResponse.getFailureMessage());
                    } else {
                        LOG.debug("Indexed {}", itemRequest.getEventKey());
                        addSuccessCount(1);
                        ret = true;
                    }
                }
            }
        } catch (Throwable t) {
            addDeferredCount(events.size());
            logError("Error sending message to OpenSearch", t);
        }
        return ret;
    }

    @Override
    public void flush() {
        // Empty flush method - OpenSearch bulk API handles flushing automatically
    }

    public boolean isAsync() {
        return true;
    }

    synchronized RestHighLevelClient getClient() {
        RestHighLevelClient client = clientRef.get();
        if (client == null) {
            synchronized (OpenSearchAuditDestination.class) {
                client = clientRef.get();
                if (client == null) {
                    client = newClient();
                    clientRef.set(client);
                }
            }
        }
        if (subject != null) {
            KerberosTicket ticket = CredentialsProviderUtil.getTGT(subject);
            try {
                if (ticket != null && new Date().getTime() > ticket.getEndTime().getTime()) {
                    clientRef.set(null);
                    CredentialsProviderUtil.ticketExpireTime80 = 0;
                    client = newClient();
                    clientRef.set(client);
                } else if (ticket != null && CredentialsProviderUtil.ticketWillExpire(ticket)) {
                    subject = CredentialsProviderUtil.login(user, password);
                }
            } catch (PrivilegedActionException e) {
                LOG.error("PrivilegedActionException:", e);
                throw new RuntimeException(e);
            }
        }
        return client;
    }

    private final AtomicLong lastLoggedAt = new AtomicLong(0);

    /**
     * Create a RestClientBuilder for OpenSearch.
     * This is a public static method to allow reuse in bootstrapper classes.
     *
     * @param urls     Comma-separated list of hostnames
     * @param protocol Protocol (http or https)
     * @param user     Username for authentication
     * @param password Password or keytab path for authentication
     * @param port     OpenSearch port
     * @return Configured RestClientBuilder
     */
    public static RestClientBuilder getRestClientBuilder(String urls, String protocol, String user, String password, int port) {
        RestClientBuilder restClientBuilder = RestClient.builder(
                MiscUtil.toArray(urls, ",").stream()
                        .map(x -> new HttpHost(x, port, protocol))
                        .toArray(HttpHost[]::new)
        );
        ThreadFactory clientThreadFactory = new ThreadFactoryBuilder()
                .setNameFormat("OpenSearch rest client %s")
                .setDaemon(true)
                .build();

        if (StringUtils.isNotBlank(user) && StringUtils.isNotBlank(password)
                && !user.equalsIgnoreCase("NONE") && !password.equalsIgnoreCase("NONE")) {
            if (password.contains("keytab") && new File(password).exists()) {
                // Kerberos authentication
                final KerberosCredentialsProvider credentialsProvider =
                        CredentialsProviderUtil.getKerberosCredentials(user, password);
                Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
                        .register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory()).build();
                restClientBuilder.setHttpClientConfigCallback(clientBuilder -> {
                    clientBuilder.setThreadFactory(clientThreadFactory);
                    clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                    clientBuilder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
                    return clientBuilder;
                });
            } else {
                // Basic authentication
                final CredentialsProvider credentialsProvider = CredentialsProviderUtil.getBasicCredentials(user, password);
                restClientBuilder.setHttpClientConfigCallback(clientBuilder -> {
                    clientBuilder.setThreadFactory(clientThreadFactory);
                    clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                    return clientBuilder;
                });
            }
        } else {
            // No authentication
            LOG.warn("OpenSearch credentials not provided. Connecting without authentication.");
            restClientBuilder.setHttpClientConfigCallback(clientBuilder -> {
                clientBuilder.setThreadFactory(clientThreadFactory);
                return clientBuilder;
            });
        }
        return restClientBuilder;
    }

    private RestHighLevelClient newClient() {
        RestHighLevelClient restHighLevelClient = null;

        try {
            if (StringUtils.isNotBlank(user) && StringUtils.isNotBlank(password)
                    && password.contains("keytab") && new File(password).exists()) {
                subject = CredentialsProviderUtil.login(user, password);
            }
            RestClientBuilder restClientBuilder = getRestClientBuilder(hosts, protocol, user, password, port);
            restHighLevelClient = new RestHighLevelClient(restClientBuilder);
            boolean exists = false;

            try {
                exists = restHighLevelClient.indices().open(new OpenIndexRequest(this.index), RequestOptions.DEFAULT).isShardsAcknowledged();
            } catch (Exception e) {
                LOG.warn("Error validating index {}", this.index);
            }

            if (exists) {
                LOG.debug("Index '{}' exists", this.index);
            } else {
                LOG.info("Index '{}' does not exist or is not accessible", this.index);
            }

            return restHighLevelClient;
        } catch (Throwable t) {
            lastLoggedAt.updateAndGet(lastLoggedAt -> {
                long now = System.currentTimeMillis();
                long elapsed = now - lastLoggedAt;
                if (elapsed > TimeUnit.MINUTES.toMillis(1)) {
                    LOG.error("Can't connect to OpenSearch server: {}", connectionString(), t);
                    return now;
                } else {
                    return lastLoggedAt;
                }
            });

            if (restHighLevelClient != null) {
                try {
                    restHighLevelClient.close();
                    LOG.debug("Closed RestHighLevelClient after failure");
                } catch (IOException e) {
                    LOG.warn("Error closing RestHighLevelClient: {}", e.getMessage(), e);
                }
            }

            return null;
        }
    }

    /**
     * Get hosts from configuration with fallback support.
     */
    private String getHosts(Properties props, String effectivePrefix) {
        String urls = getStringPropertyWithFallback(props, effectivePrefix, CONFIG_URLS, null);
        if (urls != null) {
            urls = urls.trim();
        }
        if ("NONE".equalsIgnoreCase(urls)) {
            urls = null;
        }
        return urls;
    }

    /**
     * Convert AuthzAuditEvent to OpenSearch document.
     *
     * @param auditEvent The audit event to convert
     * @return Map representing the document to be indexed
     */
    Map<String, Object> toDoc(AuthzAuditEvent auditEvent) {
        Map<String, Object> doc = new HashMap<>();
        doc.put("id", auditEvent.getEventId());
        doc.put("access", auditEvent.getAccessType());
        doc.put("enforcer", auditEvent.getAclEnforcer());
        doc.put("agent", auditEvent.getAgentId());
        doc.put("repo", auditEvent.getRepositoryName());
        doc.put("sess", auditEvent.getSessionId());
        doc.put("reqUser", auditEvent.getUser());
        doc.put("reqData", auditEvent.getRequestData());
        doc.put("resource", auditEvent.getResourcePath());
        doc.put("cliIP", auditEvent.getClientIP());
        doc.put("logType", auditEvent.getLogType());
        doc.put("result", auditEvent.getAccessResult());
        doc.put("policy", auditEvent.getPolicyId());
        doc.put("repoType", auditEvent.getRepositoryType());
        doc.put("resType", auditEvent.getResourceType());
        doc.put("reason", auditEvent.getResultReason());
        doc.put("action", auditEvent.getAction());
        Date eventTime = auditEvent.getEventTime();
        if (eventTime != null) {
            doc.put("evtTime", DATE_FORMAT.get().format(eventTime));
        } else {
            doc.put("evtTime", null);
        }
        doc.put("seq_num", auditEvent.getSeqNum());
        doc.put("event_count", auditEvent.getEventCount());
        doc.put("event_dur_ms", auditEvent.getEventDurationMS());
        doc.put("tags", auditEvent.getTags());
        doc.put("cluster", auditEvent.getClusterName());
        doc.put("zoneName", auditEvent.getZoneName());
        doc.put("agentHost", auditEvent.getAgentHostname());
        doc.put("policyVersion", auditEvent.getPolicyVersion());
        return doc;
    }
}
