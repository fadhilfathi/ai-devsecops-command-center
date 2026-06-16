# @aicc/inventory-service

Sprint 4 — Infrastructure Inventory Engine.

Provides a unified asset catalog, relationship graph, and
dependency graph for every cluster, namespace, service, and
deployment a tenant has onboarded. The engine powers the
"Infrastructure Overview" dashboard and feeds the topology
viewer.

## Endpoints

| Method | Path                                            | Description                          |
| ------ | ----------------------------------------------- | ------------------------------------ |
| GET    | `/v1/inventory/assets`                          | Unified asset catalog                |
| GET    | `/v1/inventory/assets/:id`                      | Single asset detail                  |
| GET    | `/v1/inventory/clusters`                        | Cluster inventory (cached)           |
| GET    | `/v1/inventory/namespaces`                      | Namespace inventory (cached)         |
| GET    | `/v1/inventory/services`                        | Service inventory                    |
| GET    | `/v1/inventory/deployments`                     | Deployment inventory                 |
| GET    | `/v1/inventory/graph/asset`                     | Unified Asset Graph                  |
| GET    | `/v1/inventory/graph/relationships`             | Relationship Graph                   |
| GET    | `/v1/inventory/graph/dependencies`              | Dependency Graph                     |
| GET    | `/v1/inventory/graph/dependencies/:assetId`     | Dependencies of a single asset       |
