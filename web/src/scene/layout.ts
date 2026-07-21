import type { HostRoute, HostSummary, ScanStatus } from "../types";

export type SceneNodeState = "pending" | "up" | "provisional" | "no-response" | "down";
export type SceneStyle = "original" | "map";

export const sceneStyleOptions: { value: SceneStyle; label: string }[] = [
  { value: "original", label: "Original" },
  { value: "map", label: "Map" },
];

export interface SceneNode {
  key: string;
  scanID: string;
  scanLabel: string;
  address: string;
  label: string;
  state: SceneNodeState;
  hostID?: number;
  openPortCount: number;
  webAvailable: boolean;
  position: [number, number, number];
  scale: number;
}

export interface SceneScope {
  id: string;
  label: string;
  target: string;
  status: ScanStatus;
  hosts: HostSummary[];
  routes?: HostRoute[];
}

export interface SceneGroup {
  key: string;
  label: string;
  dnsRoot?: string;
  prefix?: IPv4Prefix;
  center: [number, number, number];
  radius: number;
  prefixLength?: number;
  active: boolean;
}

export interface SceneModel {
  nodes: SceneNode[];
  groups: SceneGroup[];
  links: SceneLink[];
  waypoints: SceneWaypoint[];
  focus: [number, number, number];
}

export interface SceneLink {
  key: string;
  start: [number, number, number];
  end: [number, number, number];
}

export interface SceneWaypoint {
  key: string;
  label: string;
  position: [number, number, number];
}

export interface IPv4Prefix {
  base: number;
  length: 0 | 8 | 16 | 24;
  label: string;
}

interface IPv4Scope {
  base: number;
  count: number;
}

const maximumRenderedScope = 512;
const focusedPrefixRadius = 52;
const primaryChildRadius = 3.2;
const secondaryChildRadius = 0.18;

export function buildSceneModel(
  scopes: SceneScope[],
  style: SceneStyle = "original",
  focus?: IPv4Prefix,
): SceneModel {
  if (style === "map") return buildMapScene(scopes);
  return focus ? buildPrefixScene(scopes, style, focus) : buildScanScene(scopes, style);
}

export function prefixForTarget(target: string, length: IPv4Prefix["length"]): IPv4Prefix | undefined {
  if (length === 0) return { base: 0, length, label: "0.0.0.0/0" };
  const address = ipv4ToNumber(target.split("/")[0]);
  if (address === undefined) return undefined;
  const block = 2 ** (32 - length);
  const base = Math.floor(address / block) * block;
  return { base, length, label: `${numberToIPv4(base)}/${length}` };
}

export function scopeIntersectsPrefix(scope: SceneScope, prefix: IPv4Prefix): boolean {
  if (prefix.length === 0) return Boolean(scopeAddressNumbers(scope).length);
  const block = 2 ** (32 - prefix.length);
  return scopeAddressNumbers(scope).some((address) => Math.floor(address / block) * block === prefix.base);
}

export function commonPrefixForScopes(scopes: SceneScope[]): IPv4Prefix | undefined {
  const addresses = scopes.flatMap(scopeAddressNumbers);
  if (addresses.length === 0) return undefined;
  for (const length of [24, 16, 8] as const) {
    const candidate = prefixFromNumber(addresses[0], length);
    if (addresses.every((address) => addressInPrefix(address, candidate))) return candidate;
  }
  return prefixFromNumber(0, 0);
}

function buildScanScene(scopes: SceneScope[], style: SceneStyle): SceneModel {
  const multiple = scopes.length > 1;
  const groupDistance = multiple ? 14 + scopes.length * 1.35 : 0;
  const groups = scopes.map((scope, index) => {
    const center = multiple ? constellationPoint(index, scopes.length, groupDistance) : [0, 0, 0] as [number, number, number];
    return {
      key: scope.id,
      label: scope.label,
      center,
      radius: 7,
      active: isActive(scope.status),
    };
  });
  const nodes = mergeTemporalNodes(scopes.flatMap((scope, scopeIndex) => {
    const center = groups[scopeIndex].center;
    return buildSceneNodes(scope, style).map((node) => ({
      ...node,
      position: add(node.position, center),
      scale: multiple ? node.scale * 0.9 : node.scale,
    }));
  }));
  return { nodes, groups, links: [], waypoints: [], focus: [0, 0, 0] };
}

function buildPrefixScene(scopes: SceneScope[], style: SceneStyle, focus: IPv4Prefix): SceneModel {
  const matching = scopes.filter((scope) => scopeIntersectsPrefix(scope, focus));
  const prefixes = new Map<string, { prefix: IPv4Prefix; active: boolean; observed: boolean }>();
  prefixes.set(prefixKey(focus), { prefix: focus, active: matching.some((scope) => isActive(scope.status)), observed: matching.length > 0 });

  for (const scope of matching) {
    for (const address of scopeAddressNumbers(scope)) {
      for (let length = Math.max(8, focus.length + 8); length <= 24; length += 8) {
        const prefix = prefixFromNumber(address, length as 8 | 16 | 24);
        prefixes.set(prefixKey(prefix), {
          prefix,
          active: prefixes.get(prefixKey(prefix))?.active || isActive(scope.status),
          observed: true,
        });
      }
    }
  }

  const primaryPrefixLength = Math.min(24, focus.length + 8);

  const ordered = [...prefixes.values()].sort((left, right) => left.prefix.length - right.prefix.length || left.prefix.base - right.prefix.base);
  const centers = new Map<string, [number, number, number]>([[prefixKey(focus), [0, 0, 0]]]);
  const radii = new Map<string, number>([[prefixKey(focus), focusedPrefixRadius]]);
  for (const length of [8, 16, 24] as const) {
    if (length <= focus.length) continue;
    const relativeDepth = (length - focus.length) / 8;
    const childRadius = relativeDepth === 1 ? primaryChildRadius : secondaryChildRadius;
    for (const { prefix } of ordered.filter((candidate) => candidate.prefix.length === length)) {
      const parentLength = (length - 8) as 0 | 8 | 16;
      const parent = prefixFromNumber(prefix.base, parentLength);
      const parentKey = prefixKey(parent);
      const parentCenter = centers.get(parentKey);
      if (!parentCenter) continue;
      const parentRadius = radii.get(parentKey) ?? focusedPrefixRadius;
      const octet = Math.floor(prefix.base / 2 ** (32 - length)) % 256;
      centers.set(prefixKey(prefix), add(parentCenter, sphericalPrefixSlot(octet, parentRadius, childRadius)));
      radii.set(prefixKey(prefix), childRadius);
    }
  }

  const visiblePrefixLengths = [...new Set([focus.length, primaryPrefixLength, Math.min(24, primaryPrefixLength + 8)])];
  const visiblePrefixes = ordered.filter(({ prefix, observed }) => observed && prefix.length !== 0 && visiblePrefixLengths.includes(prefix.length));
  const groups: SceneGroup[] = visiblePrefixes.map(({ prefix, active }) => {
    const center = centers.get(prefixKey(prefix)) ?? [0, 0, 0];
    const radius = radii.get(prefixKey(prefix)) ?? primaryChildRadius;
    return {
      key: prefixKey(prefix),
      label: prefix.label,
      dnsRoot: dnsRootForPrefix(matching, prefix),
      prefix,
      center,
      radius,
      prefixLength: prefix.length,
      active,
    };
  });
  const groupRadii = new Map(groups.map((group) => [group.key, group.radius]));

  const nodes = primaryPrefixLength < 24 ? [] : mergeTemporalNodes(matching.flatMap((scope) => buildSceneNodes(scope, style).flatMap((node) => {
    const address = ipv4ToNumber(node.address);
    if (address === undefined) return [];
    const leaf = prefixFromNumber(address, 24);
    const center = centers.get(prefixKey(leaf));
    if (!center) return [];
    const hostIndex = address % 256;
    const local = positionFor(style, hostIndex, 256, node.state, node.openPortCount);
    const positionScale = (groupRadii.get(prefixKey(leaf)) ?? 7) / 7;
    const markerScale = Math.min(3, Math.max(0.75, Math.sqrt(positionScale)));
    return [{
      ...node,
      position: add(center, scaleVector(local, positionScale)),
      scale: (focus.length <= 8 ? node.scale * 0.78 : focus.length === 16 ? node.scale * 0.88 : node.scale) * markerScale,
    }];
  })));
  return { nodes, groups, links: [], waypoints: [], focus: [0, 0, 0] };
}

interface MapVertex {
  key: string;
  label: string;
  depth: number;
  target: boolean;
  position?: [number, number, number];
}

function buildMapScene(scopes: SceneScope[]): SceneModel {
  const vertices = new Map<string, MapVertex>();
  const edges = new Map<string, { key: string; from: string; to: string }>();
  const incoming = new Map<string, Set<string>>();
  vertices.set("local", { key: "local", label: "This device", depth: 0, target: false });

  function vertexKey(address: string): string {
    if (isLoopbackAddress(address)) return "local";
    return `ip:${address}`;
  }

  function ensureVertex(key: string, label: string, depth: number): MapVertex {
    const existing = vertices.get(key);
    if (existing) {
      existing.depth = Math.min(existing.depth, depth);
      return existing;
    }
    const vertex = { key, label, depth, target: false };
    vertices.set(key, vertex);
    return vertex;
  }

  function addEdge(from: string, to: string) {
    if (from === to) return;
    const key = [from, to].sort().join("—");
    if (!edges.has(key)) edges.set(key, { key, from, to });
    if (!incoming.has(to)) incoming.set(to, new Set());
    incoming.get(to)!.add(from);
  }

  for (const scope of scopes) {
    for (const route of [...(scope.routes ?? [])].sort((left, right) => left.target.localeCompare(right.target))) {
      let parent = "local";
      for (const hop of route.hops) {
        const label = hop.address || `Unknown hop ${hop.ttl}`;
        const key = hop.address ? vertexKey(hop.address) : `unknown:${route.target}:${hop.ttl}`;
        const vertex = ensureVertex(key, label, hop.ttl);
        if (hop.address === route.target) vertex.target = true;
        addEdge(parent, key);
        parent = key;
      }
      if (route.hops.length > 0) {
        const lastHop = route.hops[route.hops.length - 1];
        if (lastHop.address !== route.target) {
          const key = vertexKey(route.target);
          ensureVertex(key, route.target, lastHop.ttl + 1).target = true;
          addEdge(parent, key);
          parent = key;
        }
      }
    }
  }

  const observedByAddress = new Map<string, { node: SceneNode; count: number }>();
  for (const node of scopes.flatMap((scope) => buildSceneNodes(scope, "original").filter((candidate) => candidate.hostID !== undefined))) {
    const identity = vertexKey(node.address);
    const existing = observedByAddress.get(identity);
    if (!existing) {
      observedByAddress.set(identity, { node: { ...node, key: `topology:${identity}` }, count: 1 });
      continue;
    }
    existing.count += 1;
    existing.node.openPortCount = Math.max(existing.node.openPortCount, node.openPortCount);
    existing.node.scale = Math.max(existing.node.scale, node.scale);
    if (existing.node.label === existing.node.address && node.label !== node.address) existing.node.label = node.label;
  }

  const routeMaximumDepth = Math.max(1, ...[...vertices.values()].map((vertex) => vertex.depth));
  for (const [identity, observation] of observedByAddress) {
    ensureVertex(identity, identity === "local" ? "This device" : observation.node.address, routeMaximumDepth + 1).target = true;
  }

  const layers = new Map<number, MapVertex[]>();
  for (const vertex of vertices.values()) {
    if (!layers.has(vertex.depth)) layers.set(vertex.depth, []);
    layers.get(vertex.depth)!.push(vertex);
  }
  for (const depth of [...layers.keys()].sort((left, right) => left - right)) {
    const layer = layers.get(depth)!;
    layer.sort((left, right) => parentCenter(left.key) - parentCenter(right.key) || stableHash(left.key) - stableHash(right.key));
    const spacing = layer.length > 24 ? 1.25 : layer.length > 12 ? 1.65 : 2.4;
    layer.forEach((vertex, index) => {
      vertex.position = [(index - (layer.length - 1) / 2) * spacing, 0, depth * 2.2];
    });
  }

  function parentCenter(key: string): number {
    const positions = [...(incoming.get(key) ?? [])].flatMap((parent) => {
      const x = vertices.get(parent)?.position?.[0];
      return x === undefined ? [] : [x];
    });
    return positions.length ? positions.reduce((sum, value) => sum + value, 0) / positions.length : 0;
  }

  const nodes = [...observedByAddress.values()].map(({ node, count }) => {
    const vertex = vertices.get(vertexKey(node.address));
    return {
      ...node,
      scanLabel: count > 1 ? `${count} observations · ${node.scanLabel}` : node.scanLabel,
      position: vertex?.position ? [vertex.position[0], 0.18, vertex.position[2]] as [number, number, number] : node.position,
    };
  });
  const maximumDepth = Math.max(1, ...[...vertices.values()].map((vertex) => vertex.depth));

  const links: SceneLink[] = [...edges.values()].flatMap((edge) => {
    const from = vertices.get(edge.from);
    const to = vertices.get(edge.to);
    return from?.position && to?.position ? [{ key: edge.key, start: from.position, end: to.position }] : [];
  });
  const waypoints: SceneWaypoint[] = [...vertices.values()]
    .filter((vertex) => vertex.position && !vertex.target)
    .map((vertex) => ({ key: vertex.key, label: vertex.label, position: vertex.position! }));
  const focus: [number, number, number] = [0, 0, maximumDepth * 1.1];
  return { nodes, groups: [], links, waypoints, focus };
}

function isLoopbackAddress(address: string): boolean {
  const normalized = address.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return normalized === "localhost"
    || normalized === "::1"
    || normalized === "0:0:0:0:0:0:0:1"
    || /^127(?:\.\d{1,3}){3}$/.test(normalized);
}

function buildSceneNodes(scopeInput: SceneScope, style: SceneStyle): SceneNode[] {
  const { id: scanID, label: scanLabel, target, hosts, status } = scopeInput;
  const scope = parseIPv4Scope(target);
  const hostsByAddress = new Map(hosts.map((host) => [host.address, host]));
  const addresses = scope
    ? Array.from({ length: scope.count }, (_, index) => numberToIPv4(scope.base + index))
    : hosts.length > 0
      ? hosts.map((host) => host.address).filter(Boolean).sort(compareAddresses)
      : [target];
  const completed = status === "completed";

  return addresses.map((address, index) => {
    const host = hostsByAddress.get(address);
    const openPortCount = host?.openPortCount ?? 0;
    const state = stateFor(host, completed);
    const scale = state === "up"
      ? 0.28 + Math.min(0.3, Math.max(0, openPortCount - 1) * 0.065)
      : state === "provisional" ? 0.22 : 0.11;

    return {
      key: `${scanID}:${address}`,
      scanID,
      scanLabel,
      address,
      label: host?.hostname || address,
      state,
      hostID: host?.id,
      openPortCount,
      webAvailable: host?.webAvailable ?? false,
      position: positionFor(style, index, addresses.length, state, openPortCount),
      scale,
    };
  });
}

function mergeTemporalNodes(nodes: SceneNode[]): SceneNode[] {
  const byAddress = new Map<string, SceneNode[]>();
  for (const node of nodes) {
    const identity = node.address.trim().toLowerCase();
    const observations = byAddress.get(identity);
    if (observations) observations.push(node);
    else byAddress.set(identity, [node]);
  }
  return [...byAddress.entries()].map(([identity, observations]) => {
    const latest = observations[0];
    if (observations.length === 1) return latest;
    return {
      ...latest,
      key: `temporal:${identity}`,
      scanLabel: `${observations.length} observations · ${latest.scanLabel}`,
    };
  });
}

export function sceneExtent(nodes: SceneNode[], groups: SceneGroup[] = [], focus: [number, number, number] = [0, 0, 0]): number {
  const nodeExtent = nodes.length === 0 ? 0 : Math.max(...nodes.flatMap((node) => node.position.map((value, axis) => Math.abs(value - focus[axis]))));
  const groupExtent = groups.length === 0 ? 0 : Math.max(...groups.flatMap((group) => group.center.map((value, axis) => Math.abs(value - focus[axis]) + group.radius)));
  return Math.max(8, nodeExtent, groupExtent) * 2;
}

function positionFor(style: SceneStyle, index: number, count: number, state: SceneNodeState, openPortCount: number): [number, number, number] {
  const progress = count <= 1 ? 0.5 : index / (count - 1);
  if (style === "original" || style === "map") {
    return constellationPoint(index, count, 6, progress);
  }
  return [0, 0, 0];
}

function constellationPoint(index: number, count: number, radius: number, progressOverride?: number): [number, number, number] {
  const progress = progressOverride ?? (count <= 1 ? 0.5 : index / (count - 1));
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  const vertical = 1 - progress * 2;
  const horizontal = Math.sqrt(Math.max(0, 1 - vertical * vertical));
  const angle = index * goldenAngle;
  return [Math.cos(angle) * horizontal * radius, vertical * radius, Math.sin(angle) * horizontal * radius];
}

function sphericalPrefixSlot(octet: number, parentRadius: number, childRadius: number): [number, number, number] {
  const margin = parentRadius > 10 ? 2 : 0.08;
  return constellationPoint(octet, 256, Math.max(0.1, parentRadius - childRadius - margin));
}

function stateFor(host: HostSummary | undefined, completed: boolean): SceneNodeState {
  if (!host) return completed ? "no-response" : "pending";
  if (host.provisional) return "provisional";
  if (host.state === "up") return "up";
  return "down";
}

function parseIPv4Scope(target: string): IPv4Scope | undefined {
  const match = target.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!match) return undefined;
  const address = ipv4ToNumber(match[1]);
  const prefix = Number(match[2]);
  if (address === undefined || prefix < 0 || prefix > 32) return undefined;
  const count = 2 ** (32 - prefix);
  if (count > maximumRenderedScope) return undefined;
  return { base: Math.floor(address / count) * count, count };
}

function scopeAddressNumbers(scope: SceneScope): number[] {
  const numbers = scope.hosts.map((host) => ipv4ToNumber(host.address)).filter((value): value is number => value !== undefined);
  const target = ipv4ToNumber(scope.target.split("/")[0]);
  if (target !== undefined) numbers.push(target);
  return [...new Set(numbers)];
}

function prefixFromNumber(address: number, length: 0 | 8 | 16 | 24): IPv4Prefix {
  if (length === 0) return { base: 0, length, label: "0.0.0.0/0" };
  const block = 2 ** (32 - length);
  const base = Math.floor(address / block) * block;
  return { base, length, label: `${numberToIPv4(base)}/${length}` };
}

function dnsRootForPrefix(scopes: SceneScope[], prefix: IPv4Prefix): string | undefined {
  const names = [...new Set(scopes.flatMap((scope) => scope.hosts.flatMap((host) => {
    const address = ipv4ToNumber(host.address);
    return address !== undefined && addressInPrefix(address, prefix) && host.hostname
      ? [host.hostname.toLowerCase().replace(/\.$/, "")]
      : [];
  })))];
  if (names.length === 0) return undefined;
  if (names.length === 1) return names[0];

  const labels = names.map((name) => name.split(".").filter(Boolean).reverse());
  const shared: string[] = [];
  for (let index = 0; index < Math.min(...labels.map((parts) => parts.length)); index += 1) {
    const label = labels[0][index];
    if (!labels.every((parts) => parts[index] === label)) break;
    shared.push(label);
  }
  return shared.length > 0 ? shared.reverse().join(".") : undefined;
}

function addressInPrefix(address: number, prefix: IPv4Prefix): boolean {
  if (prefix.length === 0) return true;
  const block = 2 ** (32 - prefix.length);
  return Math.floor(address / block) * block === prefix.base;
}

function prefixKey(prefix: IPv4Prefix): string {
  return `${prefix.length}:${prefix.base}`;
}

function isActive(status: ScanStatus): boolean {
  return status === "running" || status === "queued";
}

function add(left: [number, number, number], right: [number, number, number]): [number, number, number] {
  return [left[0] + right[0], left[1] + right[1], left[2] + right[2]];
}

function scaleVector(value: [number, number, number], scale: number): [number, number, number] {
  return [value[0] * scale, value[1] * scale, value[2] * scale];
}

function stableHash(value: string): number {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function ipv4ToNumber(address: string): number | undefined {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return undefined;
  return parts.reduce((value, part) => value * 256 + part, 0);
}

function numberToIPv4(value: number): string {
  return [Math.floor(value / 256 ** 3) % 256, Math.floor(value / 256 ** 2) % 256, Math.floor(value / 256) % 256, value % 256].join(".");
}

function compareAddresses(left: string, right: string): number {
  return (ipv4ToNumber(left) ?? Number.MAX_SAFE_INTEGER) - (ipv4ToNumber(right) ?? Number.MAX_SAFE_INTEGER) || left.localeCompare(right);
}
