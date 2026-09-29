import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import type { HostReport, Session, Finding } from '../types';
import { cn, formatTlsVersion, getGradeColor, getGradeBg, getGradeLabel } from '../lib/utils';
import {
  Laptop,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  ExternalLink,
  X,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Filter,
  RefreshCw,
} from 'lucide-react';

interface TopologyNode {
  id: string;
  role: 'client' | 'server';
  ip: string;
  displayHost: string;
  ports: number[];
  sessionCount: number;
  postureGrade?: string;
  postureLabel?: string;
  postureScore?: number;
  securityStatus: 'secure' | 'warning' | 'critical' | 'no-tls';
  findingsCount: number;
  sessions: Session[];
}

interface TopologyEdge {
  id: string;
  clientId: string;
  serverId: string;
  protocol: string;
  session: Session;
  status: 'secure' | 'warning' | 'critical' | 'no-tls';
  sessionIndex: number;
  totalForPair: number;
}

interface NetworkTopologyProps {
  hosts: HostReport[];
  sourcePcapName?: string;
}

export function NetworkTopology({ hosts, sourcePcapName }: NetworkTopologyProps) {
  const navigate = useNavigate();
  const containerRef = useRef<HTMLDivElement>(null);
  const clientRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const serverRefs = useRef<Record<string, HTMLDivElement | null>>({});

  // Interaction states
  const [selectedSession, setSelectedSession] = useState<Session | null>(null);
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [hoveredEdgeId, setHoveredEdgeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Track coordinates for SVG paths
  const [nodePositions, setNodePositions] = useState<{
    clients: Record<string, { x: number; y: number }>;
    servers: Record<string, { x: number; y: number }>;
  }>({ clients: {}, servers: {} });

  // Extract all sessions
  const allSessions: Session[] = useMemo(() => {
    return hosts.flatMap(h => h.sessions);
  }, [hosts]);

  // Build client and server nodes deterministically from PCAP analysis
  const { clients, servers, edges } = useMemo(() => {
    const clientMap: Record<string, TopologyNode> = {};
    const serverMap: Record<string, TopologyNode> = {};
    const rawEdges: TopologyEdge[] = [];

    // Map hosts for fast lookup
    const hostByDstIp: Record<string, HostReport> = {};
    hosts.forEach(h => {
      hostByDstIp[h.host] = h;
      h.sessions.forEach(s => {
        hostByDstIp[s.dst_ip] = h;
      });
    });

    allSessions.forEach(session => {
      const cId = `client-${session.src_ip}`;
      const sId = `server-${session.dst_ip}`;

      // Calculate session security status
      const hasCritical = session.downgrade_suspected || session.findings.some(f => f.severity === 'critical');
      const hasWarning = session.findings.some(f => f.severity === 'high' || f.severity === 'medium') || session.cipher_strength === 'weak';
      const isPlaintext = !session.starttls_detected && !session.is_implicit_tls;

      let sessionStatus: 'secure' | 'warning' | 'critical' | 'no-tls' = 'secure';
      if (hasCritical) sessionStatus = 'critical';
      else if (hasWarning) sessionStatus = 'warning';
      else if (isPlaintext) sessionStatus = 'no-tls';

      // Client node
      if (!clientMap[cId]) {
        clientMap[cId] = {
          id: cId,
          role: 'client',
          ip: session.src_ip,
          displayHost: session.src_ip,
          ports: [session.src_port],
          sessionCount: 1,
          securityStatus: sessionStatus,
          findingsCount: session.findings.length,
          sessions: [session],
        };
      } else {
        if (!clientMap[cId].ports.includes(session.src_port)) {
          clientMap[cId].ports.push(session.src_port);
        }
        clientMap[cId].sessionCount += 1;
        clientMap[cId].findingsCount += session.findings.length;
        clientMap[cId].sessions.push(session);
        // Upgrade node status if worse
        if (sessionStatus === 'critical') clientMap[cId].securityStatus = 'critical';
        else if (sessionStatus === 'warning' && clientMap[cId].securityStatus !== 'critical') {
          clientMap[cId].securityStatus = 'warning';
        }
      }

      // Server node
      const parentHost = hostByDstIp[session.dst_ip] || hostByDstIp[`${session.dst_ip}:${session.dst_port}`];
      if (!serverMap[sId]) {
        const sGrade = parentHost?.posture_grade || 'F';
        const sLabel = parentHost?.posture_label || getGradeLabel(sGrade);
        serverMap[sId] = {
          id: sId,
          role: 'server',
          ip: session.dst_ip,
          displayHost: parentHost?.host || `${session.dst_ip}:${session.dst_port}`,
          ports: [session.dst_port],
          sessionCount: 1,
          postureGrade: sGrade,
          postureLabel: sLabel,
          postureScore: parentHost?.posture_score ?? 50,
          securityStatus: sessionStatus,
          findingsCount: session.findings.length,
          sessions: [session],
        };
      } else {
        if (!serverMap[sId].ports.includes(session.dst_port)) {
          serverMap[sId].ports.push(session.dst_port);
        }
        serverMap[sId].sessionCount += 1;
        serverMap[sId].findingsCount += session.findings.length;
        serverMap[sId].sessions.push(session);
        if (sessionStatus === 'critical') serverMap[sId].securityStatus = 'critical';
        else if (sessionStatus === 'warning' && serverMap[sId].securityStatus !== 'critical') {
          serverMap[sId].securityStatus = 'warning';
        }
      }

      // Determine display protocol (e.g. SMTPS for port 465 or implicit TLS)
      const displayProto = (session.protocol === 'SMTP' && (session.is_implicit_tls || session.dst_port === 465))
        ? 'SMTPS'
        : (session.protocol === 'IMAP' && (session.is_implicit_tls || session.dst_port === 993))
        ? 'IMAPS'
        : session.protocol;

      rawEdges.push({
        id: session.session_id,
        clientId: cId,
        serverId: sId,
        protocol: displayProto,
        session,
        status: sessionStatus,
        sessionIndex: 0,
        totalForPair: 1,
      });
    });

    // Group edge indices for parallel connections between the same pair
    const pairCounts: Record<string, number> = {};
    rawEdges.forEach(e => {
      const key = `${e.clientId}->${e.serverId}`;
      pairCounts[key] = (pairCounts[key] || 0) + 1;
    });

    const pairIndices: Record<string, number> = {};
    const finalEdges = rawEdges.map(e => {
      const key = `${e.clientId}->${e.serverId}`;
      const idx = pairIndices[key] || 0;
      pairIndices[key] = idx + 1;
      return {
        ...e,
        sessionIndex: idx,
        totalForPair: pairCounts[key] || 1,
      };
    });

    return {
      clients: Object.values(clientMap),
      servers: Object.values(serverMap),
      edges: finalEdges,
    };
  }, [allSessions, hosts]);

  // Recalculate connector anchor points whenever layout changes
  const updateAnchors = () => {
    if (!containerRef.current) return;
    const containerRect = containerRef.current.getBoundingClientRect();

    const newClients: Record<string, { x: number; y: number }> = {};
    Object.entries(clientRefs.current).forEach(([id, el]) => {
      if (el) {
        const r = el.getBoundingClientRect();
        newClients[id] = {
          x: r.right - containerRect.left,
          y: r.top + r.height / 2 - containerRect.top,
        };
      }
    });

    const newServers: Record<string, { x: number; y: number }> = {};
    Object.entries(serverRefs.current).forEach(([id, el]) => {
      if (el) {
        const r = el.getBoundingClientRect();
        newServers[id] = {
          x: r.left - containerRect.left,
          y: r.top + r.height / 2 - containerRect.top,
        };
      }
    });

    setNodePositions({ clients: newClients, servers: newServers });
  };

  useEffect(() => {
    updateAnchors();
    const handleResize = () => updateAnchors();
    window.addEventListener('resize', handleResize);
    const timer = setTimeout(updateAnchors, 150);
    return () => {
      window.removeEventListener('resize', handleResize);
      clearTimeout(timer);
    };
  }, [clients, servers, edges]);

  // Filtered edges
  const filteredEdges = useMemo(() => {
    return edges.filter(e => {
      if (protocolFilter !== 'all' && !e.protocol.toLowerCase().includes(protocolFilter.toLowerCase())) {
        return false;
      }
      if (statusFilter !== 'all' && e.status !== statusFilter) {
        return false;
      }
      if (selectedHostId) {
        return e.clientId === selectedHostId || e.serverId === selectedHostId;
      }
      return true;
    });
  }, [edges, protocolFilter, statusFilter, selectedHostId]);

  // Active highlights
  const isNodeHighlighted = (nodeId: string) => {
    if (!selectedHostId && !hoveredEdgeId && !hoveredNodeId) return true;
    if (selectedHostId) {
      if (selectedHostId === nodeId) return true;
      return filteredEdges.some(e =>
        (e.clientId === selectedHostId && e.serverId === nodeId) ||
        (e.serverId === selectedHostId && e.clientId === nodeId)
      );
    }
    if (hoveredEdgeId) {
      const edge = edges.find(e => e.id === hoveredEdgeId);
      return edge?.clientId === nodeId || edge?.serverId === nodeId;
    }
    if (hoveredNodeId) {
      if (hoveredNodeId === nodeId) return true;
      return edges.some(e =>
        (e.clientId === hoveredNodeId && e.serverId === nodeId) ||
        (e.serverId === hoveredNodeId && e.clientId === nodeId)
      );
    }
    return true;
  };

  const getStatusColor = (status: 'secure' | 'warning' | 'critical' | 'no-tls') => {
    switch (status) {
      case 'secure':
        return { stroke: '#38BDF8', glow: 'rgba(56,189,248,0.5)', text: '#38BDF8', bg: 'rgba(56,189,248,0.12)', border: 'rgba(56,189,248,0.4)' };
      case 'warning':
        return { stroke: '#F5B942', glow: 'rgba(245,185,66,0.5)', text: '#F5B942', bg: 'rgba(245,185,66,0.12)', border: 'rgba(245,185,66,0.4)' };
      case 'critical':
        return { stroke: '#FF5C5C', glow: 'rgba(255,92,92,0.6)', text: '#FF5C5C', bg: 'rgba(255,92,92,0.15)', border: 'rgba(255,92,92,0.5)' };
      case 'no-tls':
      default:
        return { stroke: '#7F948B', glow: 'rgba(127,148,139,0.3)', text: '#B8C8C0', bg: 'rgba(127,148,139,0.1)', border: 'rgba(127,148,139,0.3)' };
    }
  };

  return (
    <div className="bg-[#111215]/90 border border-white/10 rounded-xl overflow-hidden shadow-2xl mb-8">
      {/* Top Banner / Navigation Guide */}
      <div className="bg-[#16181d]/90 border-b border-white/10 px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className="p-1 rounded-lg bg-white/5 border border-white/10 text-cyan-400">
            <Info size={15} />
          </span>
          <div>
            <h2 className="text-white font-mono text-sm font-bold tracking-wider uppercase flex items-center gap-2">
              <span>PCAP Network & Session Topology</span>
              {sourcePcapName && (
                <span className="text-[11px] font-normal text-white/50 lowercase bg-white/5 px-2 py-0.5 rounded-md border border-white/10">
                  {sourcePcapName}
                </span>
              )}
            </h2>
            <p className="text-white/50 text-xs font-mono">
              Click any protocol connection badge to inspect cryptographic telemetry & forensic evidence.
            </p>
          </div>
        </div>

        {/* Filters and legend controls */}
        <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
          <div className="flex items-center gap-1 bg-white/5 px-2.5 py-1 rounded-lg border border-white/10 text-white/60">
            <Filter size={12} />
            <select
              value={protocolFilter}
              onChange={e => setProtocolFilter(e.target.value)}
              className="bg-transparent text-white focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-[#111215] text-white">All Protocols</option>
              <option value="smtp" className="bg-[#111215] text-white">SMTP / SMTPS</option>
              <option value="imap" className="bg-[#111215] text-white">IMAP / IMAPS</option>
              <option value="pop" className="bg-[#111215] text-white">POP3</option>
            </select>
          </div>

          <div className="flex items-center gap-1 bg-white/5 px-2.5 py-1 rounded-lg border border-white/10 text-white/60">
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="bg-transparent text-white focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-[#111215] text-white">All Security States</option>
              <option value="secure" className="bg-[#111215] text-white">Secure</option>
              <option value="warning" className="bg-[#111215] text-white">Warning</option>
              <option value="critical">Critical</option>
              <option value="no-tls">No TLS</option>
            </select>
          </div>

          {selectedHostId && (
            <button
              onClick={() => setSelectedHostId(null)}
              className="px-2 py-1 bg-[#0E3327] hover:bg-[#144737] text-[#8BFF7A] rounded border border-[rgba(139,255,122,0.3)] transition-colors flex items-center gap-1"
            >
              <X size={12} /> Clear Filter
            </button>
          )}
        </div>
      </div>

      {/* Main Interactive Stage */}
      <div
        ref={containerRef}
        className="relative min-h-[460px] p-6 lg:p-8 bg-[#041F17] bg-grid-pattern overflow-x-auto select-none"
      >
        {/* Stage Columns Layout */}
        <div className="min-w-[760px] flex justify-between items-start relative z-10">
          {/* CLIENT HOSTS COLUMN */}
          <div className="w-[280px] space-y-5">
            <div className="flex items-center justify-between pb-2 border-b border-[rgba(56,189,248,0.2)] text-[#38BDF8] font-mono text-xs font-bold uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <Laptop size={14} /> Client Hosts ({clients.length})
              </span>
              <span className="text-[10px] text-[#7F948B] font-normal">PCAP Sources</span>
            </div>

            {clients.map(client => {
              const isSelected = selectedHostId === client.id;
              const isHighlighted = isNodeHighlighted(client.id);

              return (
                <div
                  key={client.id}
                  ref={el => { clientRefs.current[client.id] = el; }}
                  onClick={() => setSelectedHostId(prev => (prev === client.id ? null : client.id))}
                  onMouseEnter={() => setHoveredNodeId(client.id)}
                  onMouseLeave={() => setHoveredNodeId(null)}
                  className={cn(
                    'relative rounded-xl p-3.5 transition-all duration-200 cursor-pointer border',
                    isSelected
                      ? 'bg-[#0E3327] border-[#38BDF8] shadow-[0_0_15px_rgba(56,189,248,0.35)] scale-[1.02]'
                      : isHighlighted
                      ? 'bg-[#0B2A20] border-[rgba(56,189,248,0.25)] hover:border-[#38BDF8]/60 hover:bg-[#0E3327]'
                      : 'bg-[#051812] border-[rgba(139,255,122,0.06)] opacity-35'
                  )}
                >
                  {/* Card Header */}
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 rounded bg-[#38BDF8]/15 border border-[#38BDF8]/40 flex items-center justify-center text-[#38BDF8]">
                        <Laptop size={13} />
                      </div>
                      <span className="text-[11px] font-mono font-bold text-[#38BDF8] uppercase tracking-wider">
                        Client Host
                      </span>
                    </div>

                    {client.securityStatus === 'critical' ? (
                      <ShieldAlert size={15} className="text-[#FF5C5C]" />
                    ) : client.securityStatus === 'warning' ? (
                      <AlertTriangle size={14} className="text-[#F5B942]" />
                    ) : (
                      <ShieldCheck size={15} className="text-[#38BDF8]" />
                    )}
                  </div>

                  {/* Main IP */}
                  <p className="text-white font-mono font-bold text-sm tracking-wide mb-2.5">
                    {client.ip}
                  </p>

                  {/* Details Footer */}
                  <div className="flex items-center justify-between text-[11px] font-mono text-[#7F948B] pt-2 border-t border-[rgba(56,189,248,0.1)]">
                    <span>
                      Port: <strong className="text-[#F3F7F4]">{client.ports.join(', ')}</strong>
                    </span>
                    <span>
                      Sessions: <strong className="text-[#38BDF8]">{client.sessionCount}</strong>
                    </span>
                  </div>

                  {/* Connector Pin (Right side) */}
                  <div
                    className={cn(
                      'absolute -right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 rounded-full border-2 transition-transform',
                      isSelected || hoveredNodeId === client.id
                        ? 'bg-[#38BDF8] border-white scale-125 shadow-[0_0_10px_#38BDF8]'
                        : 'bg-[#38BDF8] border-[#031B14]'
                    )}
                  />
                </div>
              );
            })}
          </div>

          {/* CENTER GAP (Reserved for connections) */}
          <div className="flex-1" />

          {/* MAIL SERVERS COLUMN */}
          <div className="w-[280px] space-y-5">
            <div className="flex items-center justify-between pb-2 border-b border-[rgba(139,255,122,0.2)] text-[#8BFF7A] font-mono text-xs font-bold uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <Server size={14} /> Mail Servers ({servers.length})
              </span>
              <span className="text-[10px] text-[#7F948B] font-normal">Analyzed Hosts</span>
            </div>

            {servers.map(server => {
              const isSelected = selectedHostId === server.id;
              const isHighlighted = isNodeHighlighted(server.id);
              const sGrade = server.postureGrade || 'F';
              const sLabel = server.postureLabel || getGradeLabel(sGrade);

              return (
                <div
                  key={server.id}
                  ref={el => { serverRefs.current[server.id] = el; }}
                  onClick={() => setSelectedHostId(prev => (prev === server.id ? null : server.id))}
                  onMouseEnter={() => setHoveredNodeId(server.id)}
                  onMouseLeave={() => setHoveredNodeId(null)}
                  className={cn(
                    'relative rounded-xl p-3.5 transition-all duration-200 cursor-pointer border',
                    isSelected
                      ? 'bg-[#0E3327] border-[#8BFF7A] shadow-[0_0_15px_rgba(139,255,122,0.35)] scale-[1.02]'
                      : isHighlighted
                      ? 'bg-[#0B2A20] border-[rgba(139,255,122,0.25)] hover:border-[#8BFF7A]/60 hover:bg-[#0E3327]'
                      : 'bg-[#051812] border-[rgba(139,255,122,0.06)] opacity-35'
                  )}
                >
                  {/* Connector Pin (Left side) */}
                  <div
                    className={cn(
                      'absolute -left-1.5 top-1/2 -translate-y-1/2 w-3 h-3 rounded-full border-2 transition-transform',
                      isSelected || hoveredNodeId === server.id
                        ? 'bg-[#8BFF7A] border-white scale-125 shadow-[0_0_10px_#8BFF7A]'
                        : 'bg-[#8BFF7A] border-[#031B14]'
                    )}
                  />

                  {/* Card Header */}
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 rounded bg-[#8BFF7A]/15 border border-[#8BFF7A]/40 flex items-center justify-center text-[#8BFF7A]">
                        <Server size={13} />
                      </div>
                      <span className="text-[11px] font-mono font-bold text-[#8BFF7A] uppercase tracking-wider">
                        Mail Server
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <span
                        className={cn(
                          'text-[10px] font-mono px-1.5 py-0.2 rounded border font-bold',
                          getGradeBg(sGrade),
                          getGradeColor(sGrade)
                        )}
                        title={`Posture: ${sGrade} (${sLabel}) • Risk ${server.postureScore}/100`}
                      >
                        {sGrade}
                      </span>
                      {server.securityStatus === 'critical' ? (
                        <ShieldAlert size={15} className="text-[#FF5C5C]" />
                      ) : server.securityStatus === 'warning' ? (
                        <AlertTriangle size={14} className="text-[#F5B942]" />
                      ) : (
                        <ShieldCheck size={15} className="text-[#8BFF7A]" />
                      )}
                    </div>
                  </div>

                  {/* Main IP / Host */}
                  <p className="text-white font-mono font-bold text-sm tracking-wide mb-2.5 truncate" title={server.displayHost}>
                    {server.ip}
                  </p>

                  {/* Details Footer */}
                  <div className="flex items-center justify-between text-[11px] font-mono text-[#7F948B] pt-2 border-t border-[rgba(139,255,122,0.1)]">
                    <span>
                      Port: <strong className="text-[#F3F7F4]">{server.ports.join(', ')}</strong>
                    </span>
                    <span>
                      Sessions: <strong className="text-[#8BFF7A]">{server.sessionCount}</strong>
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* SVG CONNECTIONS OVERLAY */}
        <svg
          className="absolute inset-0 w-full h-full pointer-events-none z-20"
          style={{ overflow: 'visible' }}
        >
          <defs>
            <filter id="glow-secure" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter id="glow-critical" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {filteredEdges.map(edge => {
            const start = nodePositions.clients[edge.clientId];
            const end = nodePositions.servers[edge.serverId];

            if (!start || !end) return null;

            // Offset parallel lines slightly so they don't overlap completely
            const yOffset = (edge.sessionIndex - (edge.totalForPair - 1) / 2) * 14;
            const y1 = start.y + yOffset;
            const y2 = end.y + yOffset;
            const x1 = start.x;
            const x2 = end.x;

            const isHovered = hoveredEdgeId === edge.id;
            const isDimmed =
              (selectedHostId && edge.clientId !== selectedHostId && edge.serverId !== selectedHostId) ||
              (hoveredNodeId && edge.clientId !== hoveredNodeId && edge.serverId !== hoveredNodeId);

            const colors = getStatusColor(edge.status);
            const isDashed = edge.status === 'warning' || edge.status === 'critical';
            const isDotted = edge.status === 'no-tls';

            // Cubic Bézier curve
            const dx = (x2 - x1) * 0.45;
            const pathD = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

            return (
              <g
                key={edge.id}
                className={cn('transition-opacity duration-200', isDimmed ? 'opacity-20' : 'opacity-100')}
              >
                {/* Background wider hit line for hover detection */}
                <path
                  d={pathD}
                  fill="none"
                  stroke="transparent"
                  strokeWidth={20}
                  className="pointer-events-auto cursor-pointer"
                  onMouseEnter={() => setHoveredEdgeId(edge.id)}
                  onMouseLeave={() => setHoveredEdgeId(null)}
                  onClick={() => setSelectedSession(edge.session)}
                />

                {/* Visible connection path */}
                <path
                  d={pathD}
                  fill="none"
                  stroke={colors.stroke}
                  strokeWidth={isHovered ? 2.8 : 1.8}
                  strokeDasharray={isDashed ? '6,4' : isDotted ? '3,3' : undefined}
                  filter={edge.status === 'critical' ? 'url(#glow-critical)' : 'url(#glow-secure)'}
                  className="transition-all duration-150"
                />
              </g>
            );
          })}
        </svg>

        {/* HTML PROTOCOL BADGES (Rendered at connection midpoints) */}
        {filteredEdges.map(edge => {
          const start = nodePositions.clients[edge.clientId];
          const end = nodePositions.servers[edge.serverId];

          if (!start || !end) return null;

          const yOffset = (edge.sessionIndex - (edge.totalForPair - 1) / 2) * 14;
          const y1 = start.y + yOffset;
          const y2 = end.y + yOffset;
          const midX = (start.x + end.x) / 2;
          const midY = (y1 + y2) / 2;

          const isHovered = hoveredEdgeId === edge.id;
          const isDimmed =
            (selectedHostId && edge.clientId !== selectedHostId && edge.serverId !== selectedHostId) ||
            (hoveredNodeId && edge.clientId !== hoveredNodeId && edge.serverId !== hoveredNodeId);

          const colors = getStatusColor(edge.status);
          const hasAlert = edge.status === 'critical' || edge.status === 'warning';

          return (
            <div
              key={`badge-${edge.id}`}
              style={{
                left: `${midX}px`,
                top: `${midY}px`,
                transform: 'translate(-50%, -50%)',
                backgroundColor: '#07241B',
                borderColor: colors.stroke,
                color: colors.text,
                boxShadow: isHovered ? `0 0 16px ${colors.glow}` : `0 2px 8px rgba(0,0,0,0.5)`,
              }}
              onMouseEnter={() => setHoveredEdgeId(edge.id)}
              onMouseLeave={() => setHoveredEdgeId(null)}
              onClick={() => setSelectedSession(edge.session)}
              className={cn(
                'absolute z-30 px-3 py-1 rounded-full cursor-pointer transition-all duration-150 flex items-center gap-1.5 shadow-lg border text-xs font-mono font-bold select-none',
                isHovered ? 'scale-110 ring-2 ring-white/40' : '',
                isDimmed ? 'opacity-25' : 'opacity-100'
              )}
              title={`Click to inspect session ${edge.session.session_id.slice(0, 8)}`}
            >
              {hasAlert && <AlertTriangle size={11} className={edge.status === 'critical' ? 'text-[#FF5C5C]' : 'text-[#F5B942]'} />}
              <span>{edge.protocol}</span>
              <span className="text-[10px] opacity-75 font-normal">({edge.session.findings.length})</span>
            </div>
          );
        })}

        {/* Mini-Map Indicator (Bottom-Right, reference image inspired) */}
        <div className="absolute right-4 bottom-4 z-20 hidden md:flex items-center gap-2 p-2 rounded-xl bg-black/80 border border-white/10 backdrop-blur-md pointer-events-none">
          <div className="flex gap-2">
            <div className="space-y-1">
              {clients.slice(0, 3).map((_, i) => (
                <div key={i} className="w-5 h-2 rounded-sm bg-[#38BDF8]/60" />
              ))}
            </div>
            <div className="space-y-1">
              {servers.slice(0, 3).map((_, i) => (
                <div key={i} className="w-5 h-2 rounded-sm bg-[#A855F7]/70" />
              ))}
            </div>
          </div>
          <span className="text-[9px] font-mono text-white/40 uppercase">Overview</span>
        </div>
      </div>

      {/* Bottom Status Legend */}
      <div className="bg-[#16181d]/90 border-t border-white/10 px-4 py-2.5 flex flex-wrap items-center justify-between text-xs font-mono text-white/50 gap-4">
        <div className="flex items-center gap-4 flex-wrap">
          <span className="font-semibold text-white">Connection Status:</span>
          <span className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 bg-[#38BDF8] inline-block" />
            <span className="text-[#38BDF8]">Secure (TLS 1.2/1.3 + PFS)</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 border-t border-dashed border-[#F5B942] inline-block" />
            <span className="text-[#F5B942]">Warning (Weak Cipher / Cert)</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 border-t border-dashed border-[#FF5C5C] inline-block" />
            <span className="text-[#FF5C5C]">Critical (Downgrade / Plaintext)</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 border-t border-dotted border-white/40 inline-block" />
            <span className="text-white/60">No TLS / Incomplete</span>
          </span>
        </div>

        <div className="text-[11px] text-white/40">
          Analyzed <strong className="text-white">{allSessions.length}</strong> email sessions • <strong className="text-white">{clients.length}</strong> clients • <strong className="text-white">{servers.length}</strong> mail servers
        </div>
      </div>

      {/* Interactive Detail Drawer for Clicked Session */}
      {selectedSession && (
        <div className="border-t border-cyan-400/30 bg-[#0c0c0c]/95 backdrop-blur-xl p-5 animate-in slide-in-from-bottom-2 duration-200">
          <div className="flex items-start justify-between pb-3 mb-4 border-b border-white/10">
            <div className="flex items-center gap-2.5">
              <span className="px-2 py-0.5 rounded-lg text-xs font-mono font-bold uppercase bg-cyan-400/15 border border-cyan-400/30 text-cyan-400">
                {selectedSession.protocol} Session
              </span>
              <div>
                <h3 className="text-white font-mono text-sm font-bold">
                  {selectedSession.src_ip}:{selectedSession.src_port} → {selectedSession.dst_ip}:{selectedSession.dst_port}
                </h3>
                <p className="text-[11px] font-mono text-white/40">
                  Session ID: {selectedSession.session_id}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => navigate(`/sessions`)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-white text-black rounded-full text-xs font-mono font-bold hover:bg-white/90 transition-colors shadow cursor-pointer"
              >
                <span>Full Session Forensics</span>
                <ExternalLink size={12} />
              </button>
              <button
                onClick={() => setSelectedSession(null)}
                className="p-1.5 rounded-lg hover:bg-white/10 text-white/50 hover:text-white transition-colors cursor-pointer"
                title="Close drawer"
              >
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Quick Session Telemetry Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 gap-3 mb-4 text-xs font-mono">
            <div className="bg-[#07241B] p-2.5 rounded border border-[rgba(139,255,122,0.1)]">
              <span className="text-[#7F948B] text-[10px] block uppercase">TLS Version</span>
              <strong className="text-[#F3F7F4]">{formatTlsVersion(selectedSession.tls_version)}</strong>
            </div>
            <div className="bg-[#07241B] p-2.5 rounded border border-[rgba(139,255,122,0.1)]">
              <span className="text-[#7F948B] text-[10px] block uppercase">Cipher Strength</span>
              <strong className={selectedSession.cipher_strength === 'strong' ? 'text-[#8BFF7A]' : selectedSession.cipher_strength === 'adequate' ? 'text-[#3DDC97]' : 'text-[#FF5C5C]'}>
                {selectedSession.cipher_strength || 'None'}
              </strong>
            </div>
            <div className="bg-[#07241B] p-2.5 rounded border border-[rgba(139,255,122,0.1)]">
              <span className="text-[#7F948B] text-[10px] block uppercase">PFS</span>
              <strong className={selectedSession.pfs ? 'text-[#8BFF7A]' : 'text-[#F5B942]'}>
                {selectedSession.pfs ? 'Enabled' : 'Disabled'}
              </strong>
            </div>
            <div className="bg-[#07241B] p-2.5 rounded border border-[rgba(139,255,122,0.1)]">
              <span className="text-[#7F948B] text-[10px] block uppercase">STARTTLS</span>
              <strong className={selectedSession.starttls_detected ? 'text-[#8BFF7A]' : 'text-[#7F948B]'}>
                {selectedSession.starttls_detected ? 'Yes' : 'No'}
              </strong>
            </div>
            <div className="bg-[#07241B] p-2.5 rounded border border-[rgba(139,255,122,0.1)]">
              <span className="text-[#7F948B] text-[10px] block uppercase">Downgrade Suspected</span>
              <strong className={selectedSession.downgrade_suspected ? 'text-[#FF5C5C]' : 'text-[#8BFF7A]'}>
                {selectedSession.downgrade_suspected ? 'YES' : 'NO'}
              </strong>
            </div>
            <div className="bg-[#07241B] p-2.5 rounded border border-[rgba(139,255,122,0.1)]">
              <span className="text-[#7F948B] text-[10px] block uppercase">Findings</span>
              <strong className={selectedSession.findings.length > 0 ? 'text-[#FF5C5C]' : 'text-[#8BFF7A]'}>
                {selectedSession.findings.length}
              </strong>
            </div>
          </div>

          {/* Session Findings with Packet Evidence */}
          {selectedSession.findings.length > 0 ? (
            <div>
              <span className="text-[11px] font-mono text-[#7F948B] uppercase tracking-wider block mb-2">
                Wire Findings & Cryptographic Evidence
              </span>
              <div className="space-y-1.5 max-h-[160px] overflow-y-auto pr-1">
                {selectedSession.findings.map(f => (
                  <div
                    key={f.finding_id}
                    className="flex items-center justify-between p-2 rounded-lg bg-white/5 border border-white/10 text-xs font-mono"
                  >
                    <div className="flex items-center gap-2">
                      <span className={cn(
                        'text-[9px] px-1.5 py-0.5 rounded font-bold uppercase',
                        f.severity === 'critical' ? 'bg-[#FF5C5C]/20 text-[#FF5C5C] border border-[#FF5C5C]/30' :
                        f.severity === 'high' ? 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/30' :
                        'bg-[#5DA9FF]/20 text-[#5DA9FF] border border-[#5DA9FF]/30'
                      )}>
                        {f.severity}
                      </span>
                      <span className="text-white">{f.description}</span>
                    </div>

                    <div className="flex items-center gap-2 text-[10px] text-white/40">
                      {f.evidence_ref?.packet_number !== undefined && (
                        <span className="bg-white/10 px-1.5 py-0.5 rounded border border-white/10 text-cyan-300">
                          Packet #{f.evidence_ref.packet_number}
                        </span>
                      )}
                      <span className="text-white/60">{f.cwe}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-2.5 rounded-lg bg-cyan-400/10 border border-cyan-400/20 text-xs font-mono text-cyan-300 flex items-center gap-2">
              <CheckCircle2 size={14} />
              <span>Zero adverse security findings detected in this session. Clean cryptographic exchange.</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
