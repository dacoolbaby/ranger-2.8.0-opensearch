# Ranger Security Admin OpenSearch Support - Modified Classes

This document records the changes made to support OpenSearch in `ranger-security-admin`.

## New Classes

- `org.apache.ranger.opensearch.OpenSearchMgr`: Manages the OpenSearch client connection and initialization.
- `org.apache.ranger.opensearch.OpenSearchUtil`: Provides utility methods for OpenSearch queries, including search request building and date range filtering.
- `org.apache.ranger.opensearch.OpenSearchAccessAuditsService`: Implements the audit log retrieval service using OpenSearch as the back-end store.

## Modified Classes

- `org.apache.ranger.biz.RangerBizUtil`: Added `AUDIT_STORE_OPEN_SEARCH` constant.
- `org.apache.ranger.biz.XAuditMgr`: Updated to inject `OpenSearchAccessAuditsService` and use it for audit log searches when the audit store type is set to `opensearch`.
- `org.apache.ranger.biz.AssetMgr`: Updated to inject `OpenSearchAccessAuditsService` and use it for access log retrieval.

## Modified Build Configuration

- `security-admin/pom.xml`: Added dependency on `ranger-audit-dest-opensearch`.

## Configuration Support

The implementation supports configuration via `ranger-admin-site.xml` using the `ranger.audit.opensearch.*` prefix, with fallback to `ranger.audit.elasticsearch.*` for backward compatibility.

### OpenSearch 与 Elasticsearch 配置对比

| 配置项 (Property) | OpenSearch 前缀 | Elasticsearch 前缀 | 说明 |
| :--- | :--- | :--- | :--- |
| URLs | `ranger.audit.opensearch.urls` | `ranger.audit.elasticsearch.urls` | OpenSearch/ES 节点的 URL 列表 |
| 协议 | `ranger.audit.opensearch.protocol` | `ranger.audit.elasticsearch.protocol` | 连接协议 (http/https) |
| 端口 | `ranger.audit.opensearch.port` | `ranger.audit.elasticsearch.port` | 服务端口 (默认 9200) |
| 用户名 | `ranger.audit.opensearch.user` | `ranger.audit.elasticsearch.user` | 用于认证的用户名 |
| 密码/Keytab | `ranger.audit.opensearch.password` | `ranger.audit.elasticsearch.password` | 认证密码或 Kerberos Keytab 路径 |
| 索引名称 | `ranger.audit.opensearch.index` | `ranger.audit.elasticsearch.index` | 审计日志存储的索引名 (默认 ranger_audits) |
| 自动初始化 | `ranger.audit.opensearch.bootstrap.enabled` | `ranger.audit.elasticsearch.bootstrap.enabled` | 是否在启动时自动创建索引 |

### 主要区别

1.  **配置前缀优先顺序**：Ranger Admin 优先读取 `ranger.audit.opensearch.*` 前缀的配置。如果未找到，则会自动回退并尝试读取对应的 `ranger.audit.elasticsearch.*` 配置。这允许用户直接沿用原有的 Elasticsearch 配置，实现无缝迁移。
2.  **特定的 OpenSearch 配置**：OpenSearch 引入了一些特有的配置项，如分片数 (`ranger.audit.opensearch.no.shards`) 和副本数 (`ranger.audit.opensearch.no.replica`)，这些配置可以在索引初始化时进行精细控制。
3.  **身份验证逻辑**：在 `OpenSearchMgr` 中，OpenSearch 认证逻辑集成了 `CredentialsProviderUtil`，能够更灵活地处理 Kerberos 认证中的 TGT 过期和自动重新登录问题。
4.  **客户端实现**：OpenSearch 使用了专门的 `opensearch-rest-high-level-client`，而 Elasticsearch 使用的是 `elasticsearch-rest-high-level-client`。尽管 API 相似，但底层通信协议和版本兼容性针对 OpenSearch 进行了优化。
