export type ScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "interrupted";

export interface Scan {
  id: string;
  target: string;
  profileId: string;
  osDetection: boolean;
  status: ScanStatus;
  arguments: string[];
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  exitCode?: number;
  output: string;
  error?: string;
  nmapVersion?: string;
  xmlOutputVersion?: string;
  hostsUp: number;
  hostsDown: number;
  hostsTotal: number;
  ownership?: Ownership;
}

export interface Capabilities {
  privileged: boolean;
  osDetection: boolean;
  toolActivity?: boolean;
  routeMapping: boolean;
  routeTool?: string;
  routeMappingReason?: string;
  providers: ProviderStatus[];
}

export interface ProviderStatus {
  capability: string;
  provider?: string;
  label?: string;
  os: string;
  status: string;
  available: boolean;
  path?: string;
  version?: string;
  reason?: string;
}

export interface RouteHop {
  ttl: number;
  address?: string;
  loss?: number;
  latencyMs?: number;
}

export interface HostRoute {
  target: string;
  tool?: string;
  hops: RouteHop[];
  error?: string;
}

export interface RouteMap {
  tool: string;
  routes: HostRoute[];
}

export interface ScanProfile {
  id: string;
  label: string;
  argumentText: string;
  arguments: string[];
  builtIn: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface HostSummary {
  id: number;
  state: string;
  address: string;
  addressType: string;
  vendor?: string;
  hostname?: string;
  openPortCount: number;
  webAvailable: boolean;
  provisional: boolean;
}

export interface HostPage {
  items: HostSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface Address {
  address: string;
  type: string;
  vendor?: string;
}

export interface Hostname {
  name: string;
  type?: string;
}

export interface Port {
  protocol: string;
  number: number;
  state: string;
  stateReason?: string;
  service?: string;
  product?: string;
  version?: string;
  extraInfo?: string;
  method?: string;
  confidence?: number;
  tunnel?: string;
}

export interface HostObservation {
  id: number;
  state: string;
  stateReason?: string;
  provisional: boolean;
  addresses: Address[];
  hostnames: Hostname[];
  ports: Port[];
  osStatus?: "matched" | "inconclusive";
  osMatches?: OSMatch[];
  ownership?: Ownership;
  evidence?: ProviderEvidence[];
}

export interface EntityRef {
  type: string;
  key: string;
}

export interface ProviderEvidence {
  id: number;
  providerRunId: string;
  provider: string;
  capability: string;
  kind: string;
  subject: EntityRef;
  object?: EntityRef;
  payloadVersion: number;
  payload: Record<string, unknown>;
  observedAt: string;
  confidence: number;
}

export interface OSMatch {
  name: string;
  accuracy: number;
  classes?: OSClass[];
}

export interface OSClass {
  type?: string;
  vendor?: string;
  family?: string;
  generation?: string;
  accuracy: number;
  cpes?: string[];
}

export interface Ownership {
  organization?: string;
  networkName?: string;
  range?: string;
  cidr?: string;
  city?: string;
  region?: string;
  country?: string;
  origin?: string;
  sources?: string[];
}

export interface ScanEvent {
  type: "scan" | "output" | "host" | "progress" | "tool" | "evidence";
  scanId?: string;
  scan?: Scan;
  host?: HostObservation;
  progress?: ScanProgress;
  tool?: ToolActivity;
  evidence?: ProviderEvidence;
  text?: string;
  stream?: "stdout" | "stderr";
}

export interface ToolActivity {
  id: string;
  label: string;
  active: boolean;
}

export interface ScanProgress {
  task: string;
  percent: string;
  remaining: string;
}
