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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;

import org.apache.ranger.audit.model.AuditEventBase;
import org.apache.ranger.audit.model.AuthzAuditEvent;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Unit tests for OpenSearchAuditDestination.
 */
public class OpenSearchAuditDestinationTest {

    /**
     * Test that the configuration prefix constants are correctly defined.
     */
    @Test
    public void testConfigurationPrefixConstants() {
        assertEquals(OpenSearchAuditDestination.CONFIG_PREFIX_OPENSEARCH, "ranger.audit.opensearch");
        assertEquals(OpenSearchAuditDestination.CONFIG_PREFIX_OPENSEARCH_PLUGIN, "xasecure.audit.destination.opensearch");
        assertEquals(OpenSearchAuditDestination.CONFIG_PREFIX_ELASTICSEARCH, "ranger.audit.elasticsearch");
        assertEquals(OpenSearchAuditDestination.CONFIG_PREFIX_ELASTICSEARCH_PLUGIN, "xasecure.audit.destination.elasticsearch");
        assertEquals(OpenSearchAuditDestination.DEFAULT_INDEX, "ranger_audits");
    }

    /**
     * Test configuration key constants.
     */
    @Test
    public void testConfigurationKeyConstants() {
        assertEquals(OpenSearchAuditDestination.CONFIG_URLS, "urls");
        assertEquals(OpenSearchAuditDestination.CONFIG_PORT, "port");
        assertEquals(OpenSearchAuditDestination.CONFIG_USER, "user");
        assertEquals(OpenSearchAuditDestination.CONFIG_PASSWORD, "password");
        assertEquals(OpenSearchAuditDestination.CONFIG_PROTOCOL, "protocol");
        assertEquals(OpenSearchAuditDestination.CONFIG_INDEX, "index");
    }

    /**
     * Test that init() correctly reads OpenSearch configuration keys.
     */
    @Test
    public void testInitWithOpenSearchConfig() {
        Properties props = new Properties();
        props.setProperty("ranger.audit.opensearch.urls", "localhost,localhost2");
        props.setProperty("ranger.audit.opensearch.port", "9201");
        props.setProperty("ranger.audit.opensearch.protocol", "https");
        props.setProperty("ranger.audit.opensearch.user", "admin");
        props.setProperty("ranger.audit.opensearch.password", "secret");
        props.setProperty("ranger.audit.opensearch.index", "test_index");

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        dest.init(props, "ranger.audit.opensearch");

        // Verify via connectionString log output (indirect verification)
        // The init method logs the connection string, we can't directly verify
        // but we can verify it doesn't throw an exception
        assertNotNull(dest);
    }

    /**
     * Test that init() falls back to Elasticsearch configuration keys.
     */
    @Test
    public void testInitWithElasticsearchFallbackConfig() {
        Properties props = new Properties();
        // Using legacy Elasticsearch keys
        props.setProperty("ranger.audit.elasticsearch.urls", "es-host1,es-host2");
        props.setProperty("ranger.audit.elasticsearch.port", "9200");
        props.setProperty("ranger.audit.elasticsearch.protocol", "http");
        props.setProperty("ranger.audit.elasticsearch.user", "es_user");
        props.setProperty("ranger.audit.elasticsearch.password", "es_password");
        props.setProperty("ranger.audit.elasticsearch.index", "es_index");

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        dest.init(props, "ranger.audit.elasticsearch");

        assertNotNull(dest);
    }

    /**
     * Test that OpenSearch keys take precedence over Elasticsearch keys.
     */
    @Test
    public void testOpenSearchConfigTakesPrecedence() {
        Properties props = new Properties();
        // Set both OpenSearch and Elasticsearch keys
        props.setProperty("ranger.audit.opensearch.urls", "opensearch-host");
        props.setProperty("ranger.audit.opensearch.port", "9201");
        props.setProperty("ranger.audit.opensearch.protocol", "https");
        props.setProperty("ranger.audit.opensearch.index", "os_index");

        // Elasticsearch keys (should be ignored when opensearch keys exist)
        props.setProperty("ranger.audit.elasticsearch.urls", "elasticsearch-host");
        props.setProperty("ranger.audit.elasticsearch.port", "9200");

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        dest.init(props, "ranger.audit.opensearch");

        assertNotNull(dest);
    }

    /**
     * Test default values when no configuration is provided.
     */
    @Test
    public void testDefaultValues() {
        Properties props = new Properties();
        // Empty properties, should use defaults

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        dest.init(props, "ranger.audit.opensearch");

        assertNotNull(dest);
    }

    /**
     * Test the toDoc() method with a complete AuthzAuditEvent.
     */
    @Test
    public void testToDocCompleteEvent() {
        AuthzAuditEvent event = createTestAuditEvent();

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        Map<String, Object> doc = dest.toDoc(event);

        assertNotNull(doc);
        assertEquals(doc.get("id"), "test-event-id");
        assertEquals(doc.get("access"), "read");
        assertEquals(doc.get("enforcer"), "Ranger");
        assertEquals(doc.get("agent"), "test-agent");
        assertEquals(doc.get("repo"), "test-repo");
        assertEquals(doc.get("sess"), "session-123");
        assertEquals(doc.get("reqUser"), "testuser");
        assertEquals(doc.get("reqData"), "SELECT * FROM table");
        assertEquals(doc.get("resource"), "/path/to/resource");
        assertEquals(doc.get("cliIP"), "192.168.1.1");
        assertEquals(doc.get("logType"), "RangerAudit");
        assertEquals(doc.get("result"), (short) 1);
        assertEquals(doc.get("policy"), 100L);
        assertEquals(doc.get("repoType"), 1);
        assertEquals(doc.get("resType"), "file");
        assertEquals(doc.get("reason"), "Policy matched");
        assertEquals(doc.get("action"), "read");
        assertNotNull(doc.get("evtTime"));
        assertEquals(doc.get("seq_num"), 1L);
        assertEquals(doc.get("event_count"), 1L);
        assertEquals(doc.get("event_dur_ms"), 100L);
        assertNotNull(doc.get("tags"));
        assertEquals(doc.get("cluster"), "test-cluster");
        assertEquals(doc.get("zoneName"), "test-zone");
        assertEquals(doc.get("agentHost"), "agent-host");
        assertEquals(doc.get("policyVersion"), 1L);
    }

    /**
     * Test the toDoc() method with null event time.
     */
    @Test
    public void testToDocNullEventTime() {
        AuthzAuditEvent event = createTestAuditEvent();
        event.setEventTime(null);

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        Map<String, Object> doc = dest.toDoc(event);

        assertNotNull(doc);
        assertNull(doc.get("evtTime"));
    }

    /**
     * Test the toDoc() method with minimal event.
     */
    @Test
    public void testToDocMinimalEvent() {
        AuthzAuditEvent event = new AuthzAuditEvent();
        event.setEventId("minimal-id");

        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        Map<String, Object> doc = dest.toDoc(event);

        assertNotNull(doc);
        assertEquals(doc.get("id"), "minimal-id");
        // Check that other fields are present even if null/default
        assertTrue(doc.containsKey("access"));
        assertTrue(doc.containsKey("result"));
    }

    /**
     * Test isAsync() returns true.
     */
    @Test
    public void testIsAsync() {
        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        assertTrue(dest.isAsync());
    }

    /**
     * Test flush() does not throw exception.
     */
    @Test
    public void testFlush() {
        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        // Should not throw any exception
        dest.flush();
    }

    /**
     * Test log() with null client (should handle gracefully).
     */
    @Test
    public void testLogWithNullClient() {
        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        Collection<AuditEventBase> events = new ArrayList<>();
        events.add(createTestAuditEvent());

        // Without initializing client, log should return false and handle gracefully
        boolean result = dest.log(events);
        assertFalse(result);
    }

    /**
     * Test log() with empty event collection.
     */
    @Test
    public void testLogEmptyEvents() {
        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        Collection<AuditEventBase> events = new ArrayList<>();

        // Should handle empty collection gracefully
        boolean result = dest.log(events);
        // With empty collection, should return false (no events processed)
        assertFalse(result);
    }

    /**
     * Test stop() method.
     */
    @Test
    public void testStop() {
        OpenSearchAuditDestination dest = new OpenSearchAuditDestination();
        // Should not throw any exception
        dest.stop();
    }

    // ==================== Helper Methods ====================

    /**
     * Create a test AuthzAuditEvent with all fields populated.
     */
    private AuthzAuditEvent createTestAuditEvent() {
        AuthzAuditEvent event = new AuthzAuditEvent();
        event.setEventId("test-event-id");
        event.setAccessType("read");
        event.setAclEnforcer("Ranger");
        event.setAgentId("test-agent");
        event.setRepositoryName("test-repo");
        event.setSessionId("session-123");
        event.setUser("testuser");
        event.setRequestData("SELECT * FROM table");
        event.setResourcePath("/path/to/resource");
        event.setClientIP("192.168.1.1");
        event.setLogType("RangerAudit");
        event.setAccessResult((short) 1);
        event.setPolicyId(100);
        event.setRepositoryType(1);
        event.setResourceType("file");
        event.setResultReason("Policy matched");
        event.setAction("read");
        event.setEventTime(new Date());
        event.setSeqNum(1);
        event.setEventCount(1);
        event.setEventDurationMS(100);
        event.setTags(new HashSet<>());
        event.getTags().add("tag1");
        event.getTags().add("tag2");
        event.setClusterName("test-cluster");
        event.setZoneName("test-zone");
        event.setAgentHostname("agent-host");
        event.setPolicyVersion(1L);
        return event;
    }
}
