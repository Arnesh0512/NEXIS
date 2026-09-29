/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: Upstream Load Balancer & Dispatch Strategy Engine
 *
 * Distributes inbound transaction volume across redundant backend nodes
 * utilizing weighted round-robin, least-connections, or consistent IP-hash
 * algorithms to maximize fault tolerance.
 */

class LoadBalancer {
  /**
   * @param {string} [strategy='ROUND_ROBIN']
   */
  constructor(strategy = "ROUND_ROBIN") {
    this.strategy = strategy;
    this.nodes = [];
    this.currentIndex = 0;
    this.totalDispatched = 0;
    this.totalFailovers = 0;
    this.rebalanceEvents = 0;
    this.dispatchHistory = [];
  }

  /**
   * Adds an upstream target node to the balancing pool.
   *
   * @param {Object} node
   * @param {string} node.id
   * @param {string} node.host
   * @param {number} node.port
   * @param {number} [node.weight=1]
   */
  addNode(node) {
    if (!node.id || !node.host || !node.port) {
      throw new Error("Invalid node configuration. Missing id, host, or port.");
    }

    this.nodes.push({
      id: node.id,
      host: node.host,
      port: node.port,
      weight: node.weight || 1,
      currentWeight: 0,
      activeConnections: 0,
      isHealthy: true,
      lastFailureTime: 0,
    });
    this.rebalanceEvents++;
  }

  /**
   * Selects an available node according to configured strategy.
   *
   * @param {string} [clientIp] Required for IP_HASH strategy
   * @returns {Object|null} Selected node
   */
  selectNode(clientIp) {
    const healthyNodes = this.nodes.filter((n) => n.isHealthy);
    if (healthyNodes.length === 0) {
      return null;
    }

    this.totalDispatched++;
    let selected = null;

    switch (this.strategy) {
      case "WEIGHTED_ROUND_ROBIN":
        selected = this.selectWeightedRoundRobin(healthyNodes);
        break;
      case "LEAST_CONNECTIONS":
        selected = this.selectLeastConnections(healthyNodes);
        break;
      case "IP_HASH":
        selected = this.selectIpHash(healthyNodes, clientIp);
        break;
      case "ROUND_ROBIN":
      default:
        selected = this.selectRoundRobin(healthyNodes);
        break;
    }

    if (selected) {
      this.recordDispatch(selected.id);
    }
    return selected;
  }

  selectRoundRobin(healthyNodes) {
    const node = healthyNodes[this.currentIndex % healthyNodes.length];
    this.currentIndex = (this.currentIndex + 1) % healthyNodes.length;
    return node;
  }

  selectWeightedRoundRobin(healthyNodes) {
    let totalWeight = 0;
    let selected = null;

    for (const node of healthyNodes) {
      node.currentWeight += node.weight;
      totalWeight += node.weight;

      if (!selected || node.currentWeight > selected.currentWeight) {
        selected = node;
      }
    }

    if (selected) {
      selected.currentWeight -= totalWeight;
    }

    return selected || healthyNodes[0];
  }

  selectLeastConnections(healthyNodes) {
    let leastConnected = healthyNodes[0];
    for (let i = 1; i < healthyNodes.length; i++) {
      if (healthyNodes[i].activeConnections < leastConnected.activeConnections) {
        leastConnected = healthyNodes[i];
      }
    }
    return leastConnected;
  }

  selectIpHash(healthyNodes, clientIp = "127.0.0.1") {
    let hash = 0;
    for (let i = 0; i < clientIp.length; i++) {
      hash = (hash << 5) - hash + clientIp.charCodeAt(i);
      hash |= 0; // Convert to 32bit integer
    }
    const positiveHash = Math.abs(hash);
    return healthyNodes[positiveHash % healthyNodes.length];
  }

  /**
   * Tracks connection opening to update least-connections state.
   */
  incrementConnections(nodeId) {
    const node = this.nodes.find((n) => n.id === nodeId);
    if (node) {
      node.activeConnections++;
    }
  }

  /**
   * Tracks connection closing to update least-connections state.
   */
  decrementConnections(nodeId) {
    const node = this.nodes.find((n) => n.id === nodeId);
    if (node && node.activeConnections > 0) {
      node.activeConnections--;
    }
  }

  /**
   * Marks a node unhealthy upon communication failure and triggers failover.
   */
  markNodeFailure(nodeId) {
    const node = this.nodes.find((n) => n.id === nodeId);
    if (node) {
      node.isHealthy = false;
      node.lastFailureTime = Date.now();
      this.totalFailovers++;
    }
  }

  /**
   * Restores node to healthy state after successful health check.
   */
  markNodeHealthy(nodeId) {
    const node = this.nodes.find((n) => n.id === nodeId);
    if (node) {
      node.isHealthy = true;
    }
  }

  /**
   * Records recent dispatch target for audit tracing.
   */
  recordDispatch(nodeId) {
    this.dispatchHistory.push({
      timestamp: Date.now(),
      nodeId,
    });
    if (this.dispatchHistory.length > 500) {
      this.dispatchHistory.shift();
    }
  }

  /**
   * Returns current pool balance summary.
   */
  getPoolStatus() {
    return {
      strategy: this.strategy,
      totalNodes: this.nodes.length,
      healthyNodes: this.nodes.filter((n) => n.isHealthy).length,
      totalDispatched: this.totalDispatched,
      totalFailovers: this.totalFailovers,
      rebalances: this.rebalanceEvents,
      nodeDetails: this.nodes.map((n) => ({
        id: n.id,
        host: n.host,
        port: n.port,
        weight: n.weight,
        healthy: n.isHealthy,
        connections: n.activeConnections,
      })),
    };
  }

  /**
   * Clears the node pool.
   */
  resetPool() {
    this.nodes = [];
    this.currentIndex = 0;
    this.totalDispatched = 0;
    this.totalFailovers = 0;
    this.dispatchHistory = [];
  }
}

module.exports = { LoadBalancer };
