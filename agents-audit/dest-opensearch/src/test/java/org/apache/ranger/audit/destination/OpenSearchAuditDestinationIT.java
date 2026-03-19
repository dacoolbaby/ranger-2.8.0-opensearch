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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.apache.ranger.audit.model.AuditEventBase;
import org.apache.ranger.audit.model.AuthzAuditEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Integration test for OpenSearchAuditDestination using Docker OpenSearch container.
 *
 * Prerequisites:
 * - Docker installed and running
 * - OpenSearch image available locally (opensearchproject/opensearch:2.19.4)
 *
 * Run with:
 *   mvn test -Dtest=OpenSearchAuditDestinationIT -DskipTests=false
 */
public class OpenSearchAuditDestinationIT {

    private static final Logger LOG = LoggerFactory.getLogger(OpenSearchAuditDestinationIT.class);

    private static final String OPENSEARCH_IMAGE = "opensearchproject/opensearch:2.19.4";
    private static final String CONTAINER_NAME = "ranger-opensearch-test";
    private static final int OPENSEARCH_PORT = 9200;
    private static final String OPENSEARCH_HOST = "127.0.0.1";
    private static final String OPENSEARCH_USER = "";  // Empty for no auth
    private static final String OPENSEARCH_PASSWORD = "";  // Empty for no auth
    private static final String TEST_INDEX = "ranger_audits_test";

    private static boolean openSearchRunning = false;
    private static String containerId = null;

    @BeforeClass
    public static void setUp() throws Exception {
        LOG.info("Setting up OpenSearch container for integration testing...");

        // Check if OpenSearch is already running
        if (isOpenSearchRunning()) {
            LOG.info("OpenSearch is already running at {}:{}", OPENSEARCH_HOST, OPENSEARCH_PORT);
            openSearchRunning = true;
            return;
        }

        // Check if container exists
        String existingContainer = getContainerIdByName(CONTAINER_NAME);
        if (existingContainer != null && !existingContainer.trim().isEmpty()) {
            LOG.info("Removing existing container: {}", existingContainer);
            executeCommand("docker rm -f " + existingContainer);
        }

        // Start OpenSearch container (disable security plugin for testing)
        LOG.info("Starting OpenSearch container with image: {}", OPENSEARCH_IMAGE);
        String command = String.format(
                "docker run -d --name %s -p %d:9200 -p 9600:9600 " +
                        "-e \"OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m\" " +
                        "-e \"DISABLE_INSTALL_DEMO_CONFIG=true\" " +
                        "-e \"DISABLE_SECURITY_PLUGIN=true\" " +
                        "-e \"discovery.type=single-node\" " +
                        "%s",
                CONTAINER_NAME, OPENSEARCH_PORT, OPENSEARCH_IMAGE);

        containerId = executeCommand(command);
        LOG.info("Container started with ID: {}", containerId);

        // Wait for OpenSearch to be ready
        LOG.info("Waiting for OpenSearch to be ready...");
        boolean ready = waitForOpenSearch(120);
        if (!ready) {
            throw new RuntimeException("OpenSearch failed to start within timeout");
        }

        openSearchRunning = true;
        LOG.info("OpenSearch is ready!");
    }

    @AfterClass
    public static void tearDown() throws Exception {
        LOG.info("Tearing down OpenSearch container...");

        if (containerId != null) {
            // Stop and remove container
            executeCommand("docker stop " + CONTAINER_NAME);
            executeCommand("docker rm " + CONTAINER_NAME);
            LOG.info("Container stopped and removed");
        }
    }

    @Test
    public void testOpenSearchConnection() throws Exception {
        assertTrue(openSearchRunning, "OpenSearch should be running");

        // Test basic connectivity
        URL url = new URL(String.format("http://%s:%d/_cluster/health", OPENSEARCH_HOST, OPENSEARCH_PORT));
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        // Add auth header if credentials are provided
        if (!OPENSEARCH_USER.isEmpty() && !OPENSEARCH_PASSWORD.isEmpty()) {
            connection.setRequestProperty("Authorization", "Basic " +
                    java.util.Base64.getEncoder().encodeToString((OPENSEARCH_USER + ":" + OPENSEARCH_PASSWORD).getBytes()));
        }

        int responseCode = connection.getResponseCode();
        assertEquals(responseCode, 200, "Should be able to connect to OpenSearch");
    }

    @Test
    public void testInitWithOpenSearchConfig() throws Exception {
        Properties props = createTestProperties(true);

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        dest.init(props, OpenSearchAuditDestination.CONFIG_PREFIX_OPENSEARCH);

        assertNotNull(dest);
        dest.stop();
    }

    @Test
    public void testInitWithElasticsearchFallbackConfig() throws Exception {
        Properties props = createTestProperties(false);

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        dest.init(props, OpenSearchAuditDestination.CONFIG_PREFIX_ELASTICSEARCH);

        assertNotNull(dest);
        dest.stop();
    }

    @Test
    public void testLogSingleEvent() throws Exception {
        Properties props = createTestProperties(true);
        props.setProperty(OpenSearchAuditDestination.CONFIG_PREFIX_OPENSEARCH + ".index", TEST_INDEX);

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        dest.init(props, OpenSearchAuditDestination.CONFIG_PREFIX_OPENSEARCH);

        // Create test event
        AuthzAuditEvent event = createTestAuditEvent("test-event-001");

        Collection<AuditEventBase> events = new ArrayList<>();
        events.add(event);

        // Log the event
        boolean result = dest.log(events);
        assertTrue(result, "Log should succeed");

        // Wait for indexing
        Thread.sleep(2000);

        // Verify the event was indexed
        boolean indexed = verifyEventIndexed(TEST_INDEX, "test-event-001");
        assertTrue(indexed, "Event should be indexed in OpenSearch");

        dest.stop();
    }

    @Test
    public void testLogBatchEvents() throws Exception {
        Properties props = createTestProperties(true);
        props.setProperty(OpenSearchAuditDestination.CONFIG_PREFIX_OPENSEARCH + ".index", TEST_INDEX);

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        dest.init(props, OpenSearchAuditDestination.CONFIG_PREFIX_OPENSEARCH);

        // Create batch of events
        Collection<AuditEventBase> events = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            events.add(createTestAuditEvent("batch-event-" + i));
        }

        // Log the batch
        boolean result = dest.log(events);
        assertTrue(result, "Batch log should succeed");

        // Wait for indexing
        Thread.sleep(2000);

        // Verify events were indexed
        for (int i = 0; i < 10; i++) {
            boolean indexed = verifyEventIndexed(TEST_INDEX, "batch-event-" + i);
            assertTrue(indexed, "Batch event " + i + " should be indexed");
        }

        dest.stop();
    }

    @Test
    public void testToDocConversion() throws Exception {
        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();

        AuthzAuditEvent event = createTestAuditEvent("conversion-test");
        java.util.Map<String, Object> doc = dest.toDoc(event);

        assertNotNull(doc);
        assertEquals(doc.get("id"), "conversion-test");
        assertEquals(doc.get("access"), "read");
        assertEquals(doc.get("enforcer"), "Ranger");
        assertEquals(doc.get("agent"), "test-agent");
        assertEquals(doc.get("repo"), "test-repo");
        assertEquals(doc.get("reqUser"), "testuser");
        assertEquals(doc.get("result"), (short) 1);
        assertEquals(doc.get("policy"), 100L);
        assertEquals(doc.get("repoType"), 1);
        assertNotNull(doc.get("evtTime"));
    }

    @Test
    public void testFlushAndStop() throws Exception {
        Properties props = createTestProperties(true);

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        dest.init(props, OpenSearchAuditDestination.CONFIG_PREFIX_OPENSEARCH);

        // Should not throw
        dest.flush();
        dest.stop();
    }

    // ==================== Helper Methods ====================

    private Properties createTestProperties(boolean useOpenSearchPrefix) {
        Properties props = new Properties();
        String prefix = useOpenSearchPrefix ?
                OpenSearchAuditDestination.CONFIG_PREFIX_OPENSEARCH :
                OpenSearchAuditDestination.CONFIG_PREFIX_ELASTICSEARCH;

        props.setProperty(prefix + ".urls", OPENSEARCH_HOST);
        props.setProperty(prefix + ".port", String.valueOf(OPENSEARCH_PORT));
        props.setProperty(prefix + ".protocol", "http");
        props.setProperty(prefix + ".user", OPENSEARCH_USER);
        props.setProperty(prefix + ".password", OPENSEARCH_PASSWORD);
        props.setProperty(prefix + ".index", TEST_INDEX);

        return props;
    }

    private AuthzAuditEvent createTestAuditEvent(String eventId) {
        AuthzAuditEvent event = new AuthzAuditEvent();
        event.setEventId(eventId);
        event.setAccessType("read");
        event.setAclEnforcer("Ranger");
        event.setAgentId("test-agent");
        event.setRepositoryName("test-repo");
        event.setSessionId("session-" + eventId);
        event.setUser("testuser");
        event.setRequestData("SELECT * FROM test_table");
        event.setResourcePath("/path/to/resource");
        event.setClientIP("192.168.1.100");
        event.setLogType("RangerAudit");
        event.setAccessResult((short) 1);
        event.setPolicyId(100);
        event.setRepositoryType(1);
        event.setResourceType("table");
        event.setResultReason("Access allowed by policy");
        event.setAction("read");
        event.setEventTime(new Date());
        event.setSeqNum(System.currentTimeMillis());
        event.setEventCount(1);
        event.setEventDurationMS(50);
        event.setTags(new HashSet<>());
        event.getTags().add("tag1");
        event.getTags().add("tag2");
        event.setClusterName("test-cluster");
        event.setZoneName("test-zone");
        event.setAgentHostname("test-agent-host");
        event.setPolicyVersion(1L);
        return event;
    }

    private static boolean isOpenSearchRunning() {
        try {
            URL url = new URL(String.format("http://%s:%d/_cluster/health", OPENSEARCH_HOST, OPENSEARCH_PORT));
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            // Add auth header if credentials are provided
            if (!OPENSEARCH_USER.isEmpty() && !OPENSEARCH_PASSWORD.isEmpty()) {
                connection.setRequestProperty("Authorization", "Basic " +
                        java.util.Base64.getEncoder().encodeToString((OPENSEARCH_USER + ":" + OPENSEARCH_PASSWORD).getBytes()));
            }
            connection.setConnectTimeout(5000);
            int responseCode = connection.getResponseCode();
            return responseCode == 200;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean waitForOpenSearch(int timeoutSeconds) throws Exception {
        long startTime = System.currentTimeMillis();
        long timeoutMs = timeoutSeconds * 1000L;

        while (System.currentTimeMillis() - startTime < timeoutMs) {
            if (isOpenSearchRunning()) {
                return true;
            }
            Thread.sleep(2000);
            LOG.info("Still waiting for OpenSearch...");
        }
        return false;
    }

    private static String getContainerIdByName(String name) throws Exception {
        try {
            String result = executeCommand("docker ps -aq -f name=" + name);
            return (result != null && !result.trim().isEmpty()) ? result.trim() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String executeCommand(String command) throws Exception {
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", command);
        processBuilder.redirectErrorStream(true);

        Process process = processBuilder.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0 && !command.contains("ps -aq")) {
            throw new RuntimeException("Command failed with exit code " + exitCode + ": " + command + "\nOutput: " + output);
        }

        return output.toString().trim();
    }

    private boolean verifyEventIndexed(String index, String eventId) throws Exception {
        try {
            URL url = new URL(String.format("http://%s:%d/%s/_doc/%s", OPENSEARCH_HOST, OPENSEARCH_PORT, index, eventId));
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            // Add auth header if credentials are provided
            if (!OPENSEARCH_USER.isEmpty() && !OPENSEARCH_PASSWORD.isEmpty()) {
                connection.setRequestProperty("Authorization", "Basic " +
                        java.util.Base64.getEncoder().encodeToString((OPENSEARCH_USER + ":" + OPENSEARCH_PASSWORD).getBytes()));
            }
            connection.setConnectTimeout(5000);

            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                return response.toString().contains("\"found\":true");
            }
            return false;
        } catch (Exception e) {
            LOG.warn("Error verifying event indexed: {}", e.getMessage());
            return false;
        }
    }
}
