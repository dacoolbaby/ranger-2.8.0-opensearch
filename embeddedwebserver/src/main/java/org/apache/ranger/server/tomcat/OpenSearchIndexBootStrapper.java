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

package org.apache.ranger.server.tomcat;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.ranger.authorization.credutils.CredentialsProviderUtil;
import org.apache.ranger.authorization.credutils.kerberos.KerberosCredentialsProvider;
import org.apache.ranger.credentialapi.CredentialReader;
import org.opensearch.action.admin.indices.open.OpenIndexRequest;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.client.indices.CreateIndexRequest;
import org.opensearch.client.indices.CreateIndexResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;

/**
 * Bootstrapper class to create OpenSearch index for Ranger audit logs.
 *
 * This class provides backward compatibility with Elasticsearch configuration keys.
 * Configuration property key resolution order:
 * 1. ranger.audit.opensearch.* (new preferred prefix)
 * 2. ranger.audit.elasticsearch.* (legacy prefix for backward compatibility)
 *
 * This allows users to migrate from Elasticsearch to OpenSearch without changing
 * their existing configuration files.
 */
public class OpenSearchIndexBootStrapper extends Thread {

    private static final Logger LOG = Logger.getLogger(OpenSearchIndexBootStrapper.class.getName());

    // OpenSearch configuration keys (new preferred)
    private static final String OS_CONFIG_USERNAME = "ranger.audit.opensearch.user";
    private static final String OS_CONFIG_PASSWORD = "ranger.audit.opensearch.password";
    private static final String OS_CONFIG_URLS = "ranger.audit.opensearch.urls";
    private static final String OS_CONFIG_PORT = "ranger.audit.opensearch.port";
    private static final String OS_CONFIG_PROTOCOL = "ranger.audit.opensearch.protocol";
    private static final String OS_CONFIG_INDEX = "ranger.audit.opensearch.index";
    private static final String OS_TIME_INTERVAL = "ranger.audit.opensearch.time.interval";
    private static final String OS_NO_SHARDS = "ranger.audit.opensearch.no.shards";
    private static final String OS_NO_REPLICA = "ranger.audit.opensearch.no.replica";
    private static final String OS_CREDENTIAL_ALIAS = "ranger.audit.opensearch.credential.alias";
    private static final String OS_BOOTSTRAP_MAX_RETRY = "ranger.audit.opensearch.max.retry";
    private static final String OS_BOOTSTRAP_ENABLED = "ranger.audit.opensearch.bootstrap.enabled";

    // Elasticsearch configuration keys (legacy for backward compatibility)
    private static final String ES_CONFIG_USERNAME = "ranger.audit.elasticsearch.user";
    private static final String ES_CONFIG_PASSWORD = "ranger.audit.elasticsearch.password";
    private static final String ES_CONFIG_URLS = "ranger.audit.elasticsearch.urls";
    private static final String ES_CONFIG_PORT = "ranger.audit.elasticsearch.port";
    private static final String ES_CONFIG_PROTOCOL = "ranger.audit.elasticsearch.protocol";
    private static final String ES_CONFIG_INDEX = "ranger.audit.elasticsearch.index";
    private static final String ES_TIME_INTERVAL = "ranger.audit.elasticsearch.time.interval";
    private static final String ES_NO_SHARDS = "ranger.audit.elasticsearch.no.shards";
    private static final String ES_NO_REPLICA = "ranger.audit.elasticsearch.no.replica";
    private static final String ES_CREDENTIAL_ALIAS = "ranger.audit.elasticsearch.credential.alias";
    private static final String ES_BOOTSTRAP_MAX_RETRY = "ranger.audit.elasticsearch.max.retry";
    private static final String ES_BOOTSTRAP_ENABLED = "ranger.audit.elasticsearch.bootstrap.enabled";

    private static final String CREDENTIAL_PROVIDER_PATH = "ranger.credential.provider.path";

    private static final String DEFAULT_INDEX_NAME = "ranger_audits";
    private static final String OS_RANGER_AUDIT_SCHEMA_FILE = "ranger_opensearch_schema.json";
    private static final String ES_RANGER_AUDIT_SCHEMA_FILE = "ranger_es_schema.json";

    private static final long DEFAULT_TIME_INTERVAL_MS = 60000L;
    private static final int TRY_UNTIL_SUCCESS = -1;
    private static final int DEFAULT_BOOTSTRAP_MAX_RETRY = 30;

    private final AtomicLong lastLoggedAt = new AtomicLong(0);
    private volatile RestHighLevelClient client = null;
    private Long time_interval;

    private String user;
    private String password;
    private String hosts;
    private String protocol;
    private String index;
    private String schema_json;

    private int port;
    private int max_retry;
    private int retry_counter = 0;
    private int no_of_replicas;
    private int no_of_shards;
    private boolean is_completed = false;
    private boolean usingLegacyConfig = false;

    public OpenSearchIndexBootStrapper() throws IOException {
        LOG.info("Starting Ranger audit schema setup in OpenSearch.");

        // Check if OpenSearch configuration exists, otherwise fallback to Elasticsearch
        String urls = getConfigWithFallback(OS_CONFIG_URLS, ES_CONFIG_URLS, null);
        usingLegacyConfig = (urls == null);

        if (usingLegacyConfig) {
            LOG.info("Using legacy Elasticsearch configuration keys. Consider migrating to opensearch.* prefix.");
        }

        time_interval = getLongConfigWithFallback(OS_TIME_INTERVAL, ES_TIME_INTERVAL, DEFAULT_TIME_INTERVAL_MS);
        user = getConfigWithFallback(OS_CONFIG_USERNAME, ES_CONFIG_USERNAME, null);
        hosts = EmbeddedServerUtil.getHosts(urls);
        port = getIntConfigWithFallback(OS_CONFIG_PORT, ES_CONFIG_PORT, 9200);
        protocol = getConfigWithFallback(OS_CONFIG_PROTOCOL, ES_CONFIG_PROTOCOL, "http");
        index = getConfigWithFallback(OS_CONFIG_INDEX, ES_CONFIG_INDEX, DEFAULT_INDEX_NAME);
        password = getConfigWithFallback(OS_CONFIG_PASSWORD, ES_CONFIG_PASSWORD, null);

        no_of_replicas = getIntConfigWithFallback(OS_NO_REPLICA, ES_NO_REPLICA, 1);
        no_of_shards = getIntConfigWithFallback(OS_NO_SHARDS, ES_NO_SHARDS, 1);
        max_retry = getIntConfigWithFallback(OS_BOOTSTRAP_MAX_RETRY, ES_BOOTSTRAP_MAX_RETRY, DEFAULT_BOOTSTRAP_MAX_RETRY);

        // Load schema file
        String jarLocation = null;
        try {
            jarLocation = this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
        } catch (Exception ex) {
            LOG.severe("Error finding base location:" + ex.toString());
        }

        String rangerHomeDir = new File(jarLocation).getParentFile().getParentFile().getParentFile().getPath();

        // Try OpenSearch schema first, then fallback to ES schema
        Path os_schema_path = Paths.get(rangerHomeDir, "contrib", "opensearch_for_audit_setup", "conf", OS_RANGER_AUDIT_SCHEMA_FILE);
        Path es_schema_path = Paths.get(rangerHomeDir, "contrib", "elasticsearch_for_audit_setup", "conf", ES_RANGER_AUDIT_SCHEMA_FILE);

        if (Files.exists(os_schema_path)) {
            schema_json = new String(Files.readAllBytes(os_schema_path), StandardCharsets.UTF_8);
            LOG.info("Loaded OpenSearch schema from: " + os_schema_path);
        } else if (Files.exists(es_schema_path)) {
            schema_json = new String(Files.readAllBytes(es_schema_path), StandardCharsets.UTF_8);
            LOG.info("Loaded Elasticsearch schema (compatible with OpenSearch) from: " + es_schema_path);
        } else {
            // Use default minimal schema if no schema file found
            schema_json = getDefaultSchema();
            LOG.warning("No schema file found. Using default minimal schema.");
        }

        // Handle credential provider
        String providerPath = EmbeddedServerUtil.getConfig(CREDENTIAL_PROVIDER_PATH);
        String credentialAlias = getConfigWithFallback(OS_CREDENTIAL_ALIAS, ES_CREDENTIAL_ALIAS, OS_CONFIG_PASSWORD);
        String keyStoreFileType = EmbeddedServerUtil.getConfig("ranger.keystore.file.type", KeyStore.getDefaultType());

        if (providerPath != null && credentialAlias != null) {
            try {
                String decryptedPassword = CredentialReader.getDecryptedString(providerPath.trim(), credentialAlias.trim(), keyStoreFileType);
                if (StringUtils.isNotBlank(decryptedPassword) && !"none".equalsIgnoreCase(decryptedPassword.trim())) {
                    password = decryptedPassword;
                }
            } catch (Exception e) {
                LOG.warning("Failed to read credential from provider: " + e.getMessage());
            }
        }
    }

    /**
     * Get configuration value with fallback from OpenSearch to Elasticsearch prefix.
     */
    private String getConfigWithFallback(String osKey, String esKey, String defaultValue) {
        String value = EmbeddedServerUtil.getConfig(osKey);
        if (value == null || value.trim().isEmpty()) {
            value = EmbeddedServerUtil.getConfig(esKey);
        }
        return (value != null && !value.trim().isEmpty()) ? value : defaultValue;
    }

    /**
     * Get integer configuration value with fallback from OpenSearch to Elasticsearch prefix.
     */
    private int getIntConfigWithFallback(String osKey, String esKey, int defaultValue) {
        String value = EmbeddedServerUtil.getConfig(osKey);
        if (value == null || value.trim().isEmpty()) {
            value = EmbeddedServerUtil.getConfig(esKey);
        }
        if (value != null && !value.trim().isEmpty()) {
            try {
                return Integer.parseInt(value.trim());
            } catch (NumberFormatException e) {
                LOG.warning("Invalid integer value for config: " + e.getMessage());
            }
        }
        return defaultValue;
    }

    /**
     * Get long configuration value with fallback from OpenSearch to Elasticsearch prefix.
     */
    private long getLongConfigWithFallback(String osKey, String esKey, long defaultValue) {
        String value = EmbeddedServerUtil.getConfig(osKey);
        if (value == null || value.trim().isEmpty()) {
            value = EmbeddedServerUtil.getConfig(esKey);
        }
        if (value != null && !value.trim().isEmpty()) {
            try {
                return Long.parseLong(value.trim());
            } catch (NumberFormatException e) {
                LOG.warning("Invalid long value for config: " + e.getMessage());
            }
        }
        return defaultValue;
    }

    /**
     * Get default minimal schema for Ranger audits.
     */
    private String getDefaultSchema() {
        return "{\n" +
                "  \"properties\": {\n" +
                "    \"id\": { \"type\": \"keyword\" },\n" +
                "    \"access\": { \"type\": \"keyword\" },\n" +
                "    \"enforcer\": { \"type\": \"keyword\" },\n" +
                "    \"agent\": { \"type\": \"keyword\" },\n" +
                "    \"repo\": { \"type\": \"keyword\" },\n" +
                "    \"sess\": { \"type\": \"keyword\" },\n" +
                "    \"reqUser\": { \"type\": \"keyword\" },\n" +
                "    \"reqData\": { \"type\": \"text\" },\n" +
                "    \"resource\": { \"type\": \"keyword\" },\n" +
                "    \"cliIP\": { \"type\": \"keyword\" },\n" +
                "    \"logType\": { \"type\": \"keyword\" },\n" +
                "    \"result\": { \"type\": \"integer\" },\n" +
                "    \"policy\": { \"type\": \"long\" },\n" +
                "    \"repoType\": { \"type\": \"integer\" },\n" +
                "    \"resType\": { \"type\": \"keyword\" },\n" +
                "    \"reason\": { \"type\": \"text\" },\n" +
                "    \"action\": { \"type\": \"keyword\" },\n" +
                "    \"evtTime\": { \"type\": \"date\" },\n" +
                "    \"seq_num\": { \"type\": \"long\" },\n" +
                "    \"event_count\": { \"type\": \"long\" },\n" +
                "    \"event_dur_ms\": { \"type\": \"long\" },\n" +
                "    \"tags\": { \"type\": \"keyword\" },\n" +
                "    \"cluster\": { \"type\": \"keyword\" },\n" +
                "    \"zoneName\": { \"type\": \"keyword\" },\n" +
                "    \"agentHost\": { \"type\": \"keyword\" },\n" +
                "    \"policyVersion\": { \"type\": \"long\" }\n" +
                "  }\n" +
                "}";
    }

    private String connectionString() {
        return String.format(Locale.ROOT, "User:%s, %s://%s:%s/%s", user, protocol, hosts, port, index);
    }

    @Override
    public void run() {
        LOG.info("Started OpenSearch index bootstrapper");

        // Check if bootstrap is enabled
        boolean bootstrapEnabled = getBooleanConfigWithFallback(OS_BOOTSTRAP_ENABLED, ES_BOOTSTRAP_ENABLED, true);
        if (!bootstrapEnabled) {
            LOG.info("OpenSearch bootstrap is disabled. Skipping index creation.");
            return;
        }

        if (StringUtils.isNotBlank(hosts)) {
            LOG.info("OpenSearch hosts=" + hosts + ", index=" + index);

            while (!is_completed && (max_retry == TRY_UNTIL_SUCCESS || retry_counter < max_retry)) {
                try {
                    LOG.info("Attempting to connect to OpenSearch");
                    if (connect()) {
                        LOG.info("Connection to OpenSearch established successfully");
                        if (createIndex()) {
                            is_completed = true;
                            break;
                        } else {
                            logErrorMessageAndWait("Error while performing operations on OpenSearch. ", null);
                        }
                    } else {
                        logErrorMessageAndWait(
                                "Cannot connect to OpenSearch. Please check the OpenSearch related configs. ",
                                null);
                    }
                } catch (Exception ex) {
                    logErrorMessageAndWait("Error while validating OpenSearch index ", ex);
                }
            }
        } else {
            LOG.severe("OpenSearch hosts value is empty. Please set property " + OS_CONFIG_URLS +
                    " or " + ES_CONFIG_URLS + " for backward compatibility.");
        }
    }

    /**
     * Get boolean configuration value with fallback from OpenSearch to Elasticsearch prefix.
     */
    private boolean getBooleanConfigWithFallback(String osKey, String esKey, boolean defaultValue) {
        String value = EmbeddedServerUtil.getConfig(osKey);
        if (value == null || value.trim().isEmpty()) {
            value = EmbeddedServerUtil.getConfig(esKey);
        }
        if (value != null && !value.trim().isEmpty()) {
            return Boolean.parseBoolean(value.trim());
        }
        return defaultValue;
    }

    private synchronized boolean connect() {
        if (client == null) {
            synchronized (OpenSearchIndexBootStrapper.class) {
                if (client == null) {
                    try {
                        createClient();
                    } catch (Exception ex) {
                        LOG.severe("Can't connect to OpenSearch server. host=" + hosts + ", index=" + index + ex);
                    }
                }
            }
        }
        return client != null;
    }

    private void createClient() {
        try {
            RestClientBuilder restClientBuilder = getRestClientBuilder(hosts, protocol, user, password, port);
            client = new RestHighLevelClient(restClientBuilder);
            LOG.info("OpenSearch client created successfully");
        } catch (Throwable t) {
            lastLoggedAt.updateAndGet(lastLoggedAt -> {
                long now = System.currentTimeMillis();
                long elapsed = now - lastLoggedAt;
                if (elapsed > TimeUnit.MINUTES.toMillis(1)) {
                    LOG.severe("Can't connect to OpenSearch server: " + connectionString() + t);
                    return now;
                } else {
                    return lastLoggedAt;
                }
            });
        }
    }

    /**
     * Create a RestClientBuilder for OpenSearch.
     * This is a public static method to allow reuse.
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
                EmbeddedServerUtil.toArray(urls, ",").stream()
                        .map(x -> new HttpHost(x, port, protocol))
                        .<HttpHost>toArray(i -> new HttpHost[i])
        );

        if (StringUtils.isNotBlank(user) && StringUtils.isNotBlank(password)
                && !user.equalsIgnoreCase("NONE") && !password.equalsIgnoreCase("NONE")) {
            if (password.contains("keytab") && new File(password).exists()) {
                // Kerberos authentication
                final KerberosCredentialsProvider credentialsProvider =
                        CredentialsProviderUtil.getKerberosCredentials(user, password);
                Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
                        .register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory()).build();
                restClientBuilder.setHttpClientConfigCallback(clientBuilder -> {
                    clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                    clientBuilder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
                    return clientBuilder;
                });
            } else {
                // Basic authentication
                final CredentialsProvider credentialsProvider =
                        CredentialsProviderUtil.getBasicCredentials(user, password);
                restClientBuilder.setHttpClientConfigCallback(clientBuilder ->
                        clientBuilder.setDefaultCredentialsProvider(credentialsProvider));
            }
        } else {
            // No authentication
            LOG.warning("OpenSearch credentials not provided. Connecting without authentication.");
            restClientBuilder.setHttpClientConfigCallback(clientBuilder -> clientBuilder);
        }
        return restClientBuilder;
    }

    private boolean createIndex() {
        boolean exists = false;

        if (client == null) {
            connect();
        }

        if (client != null) {
            try {
                exists = client.indices().open(new OpenIndexRequest(this.index), RequestOptions.DEFAULT)
                        .isShardsAcknowledged();
            } catch (Exception e) {
                LOG.info("Index " + this.index + " not available or does not exist.");
            }

            if (!exists) {
                LOG.info("Index does not exist. Attempting to create index: " + this.index);
                CreateIndexRequest request = new CreateIndexRequest(this.index);

                if (this.no_of_shards >= 0 && this.no_of_replicas >= 0) {
                    request.settings(Settings.builder()
                            .put("index.number_of_shards", this.no_of_shards)
                            .put("index.number_of_replicas", this.no_of_replicas));
                }

                request.mapping(schema_json, XContentType.JSON);
                request.setMasterTimeout(TimeValue.timeValueMinutes(1));
                request.setTimeout(TimeValue.timeValueMinutes(2));

                try {
                    CreateIndexResponse createIndexResponse = client.indices().create(request, RequestOptions.DEFAULT);
                    if (createIndexResponse != null) {
                        exists = client.indices().open(new OpenIndexRequest(this.index), RequestOptions.DEFAULT)
                                .isShardsAcknowledged();
                        if (exists) {
                            LOG.info("Index " + this.index + " created successfully.");
                        }
                    }
                } catch (Exception e) {
                    LOG.severe("Unable to create Index. Reason: " + e.toString());
                    e.printStackTrace();
                }
            } else {
                LOG.info("Index " + this.index + " already exists.");
            }
        }
        return exists;
    }

    private void logErrorMessageAndWait(String msg, Exception exception) {
        retry_counter++;
        String attemptMessage;

        if (max_retry != TRY_UNTIL_SUCCESS) {
            attemptMessage = (retry_counter == max_retry)
                    ? "Maximum attempts reached for setting up OpenSearch."
                    : "[retrying after " + time_interval + " ms]. No. of attempts left: "
                    + (max_retry - retry_counter) + ". Maximum attempts: " + max_retry;
        } else {
            attemptMessage = "[retrying after " + time_interval + " ms]";
        }

        StringBuilder errorBuilder = new StringBuilder();
        errorBuilder.append(msg);
        if (exception != null) {
            errorBuilder.append("Error: ").append(exception.getMessage()).append(". ");
        }
        errorBuilder.append(attemptMessage);
        LOG.severe(errorBuilder.toString());

        try {
            Thread.sleep(time_interval);
        } catch (InterruptedException ex) {
            LOG.info("Sleep interrupted: " + ex.getMessage());
            Thread.currentThread().interrupt();
        }
    }
}
