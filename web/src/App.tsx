import { CSSProperties, FormEvent, KeyboardEvent as ReactKeyboardEvent, lazy, MouseEvent as ReactMouseEvent, PointerEvent as ReactPointerEvent, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { cancelScan, createProfile, deleteProfile, deleteScan, getCapabilities, getHost, getScan, listHosts, listProfiles, listRoutes, listScans, listTools, mapRoute, startScan, updateProfile } from "./api";
import { buildSceneModel, commonPrefixForScopes, prefixForTarget, sceneStyleOptions, scopeIntersectsPrefix, type IPv4Prefix, type SceneNode, type SceneScope, type SceneStyle } from "./scene/layout";
import type { Capabilities, HostObservation, HostPage, HostSummary, Ownership, ProviderEvidence, RouteMap, Scan, ScanEvent, ScanProfile, ScanProgress, ScanStatus, ToolActivity } from "./types";

const finalStatuses = new Set<ScanStatus>(["completed", "failed", "cancelled", "interrupted"]);
const maximumRecentScans = 8;
const defaultProfileID = "builtin:quick";
const defaultHistoryWidth = 210;
const minimumHistoryWidth = 180;
const maximumHistoryWidth = 420;
type SceneView = "selected" | "selection" | "recent" | "range24" | "range16" | "range8" | "all";
interface RouteMappingProgress {
  scopeKey: string;
  completed: number;
  total: number;
  failed: number;
  tools: string[];
}
interface ScanSeries {
  key: string;
  target: string;
  address?: string;
  scans: Scan[];
}
type HistorySort = "date" | "name" | "ip";
const NetworkScene = lazy(() => import("./scene/NetworkScene").then((module) => ({ default: module.NetworkScene })));

export default function App() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedID, setSelectedID] = useState<string>();
  const [selected, setSelected] = useState<Scan>();
  const [target, setTarget] = useState("");
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [profileID, setProfileID] = useState(defaultProfileID);
  const [profileText, setProfileText] = useState("");
  const [profilesOpen, setProfilesOpen] = useState(false);
  const [capabilities, setCapabilities] = useState<Capabilities>();
  const [osDetection, setOSDetection] = useState(false);
  const [output, setOutput] = useState("");
  const [hosts, setHosts] = useState<HostPage>();
  const [hostPages, setHostPages] = useState<Record<string, HostPage>>({});
  const [selectedKey, setSelectedKey] = useState<string>();
  const [selectedHost, setSelectedHost] = useState<HostObservation>();
  const [progress, setProgress] = useState<ScanProgress>();
  const [scanTools, setScanTools] = useState<Record<string, ToolActivity>>({});
  const [sceneStyle, setSceneStyle] = useState<SceneStyle>("original");
  const [sceneView, setSceneView] = useState<SceneView>("selected");
  const [includedScanIDs, setIncludedScanIDs] = useState<Set<string>>();
  const [navigationPrefix, setNavigationPrefix] = useState<IPv4Prefix>();
  const [routeMaps, setRouteMaps] = useState<Record<string, RouteMap>>({});
  const [routeProgress, setRouteProgress] = useState<RouteMappingProgress>();
  const [openScanMenu, setOpenScanMenu] = useState<string>();
  const [bulkActionPending, setBulkActionPending] = useState(false);
  const [expandedSeries, setExpandedSeries] = useState<Set<string>>(new Set());
  const [helpOpen, setHelpOpen] = useState(false);
  const [historyWidth, setHistoryWidth] = useState(() => storedHistoryWidth());
  const [historySort, setHistorySort] = useState<HistorySort>("date");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [now, setNow] = useState(Date.now());
  const outputRef = useRef<HTMLPreElement>(null);
  const loadedRoutes = useRef(new Set<string>());
  const loadingHostPages = useRef(new Set<string>());
  const osDetectionInitialized = useRef(false);
  const autoHostRequest = useRef<string | undefined>(undefined);
  const historyResize = useRef<{ pointerID: number; startX: number; startWidth: number } | undefined>(undefined);

  const refreshScans = useCallback(async () => {
    try {
      const result = await listScans();
      setScans(result);
      setIncludedScanIDs((current) => current ?? new Set(result[0] ? [result[0].id] : []));
      setSelectedID((current) => current ?? result[0]?.id);
      setError("");
    } catch (requestError) {
      setError(messageFor(requestError));
    }
  }, []);

  const refreshProfiles = useCallback(async () => {
    try {
      const result = await listProfiles();
      setProfiles(result);
      const selected = result.find((profile) => profile.id === defaultProfileID)
        ?? result[0];
      if (selected) {
        setProfileID(selected.id);
        setProfileText((current) => current || selected.argumentText);
      }
    } catch (requestError) {
      setError(messageFor(requestError));
    }
  }, []);

  const refreshHosts = useCallback(async (scanID: string) => {
    try {
      const page = await listHosts(scanID);
      setHosts(page);
      setHostPages((current) => ({ ...current, [scanID]: page }));
    } catch (requestError) {
      setError(messageFor(requestError));
    }
  }, []);

  useEffect(() => {
    void refreshScans();
  }, [refreshScans]);

  useEffect(() => {
    void refreshProfiles();
  }, [refreshProfiles]);

  useEffect(() => {
    void getCapabilities()
      .then((result) => {
        setCapabilities(result);
        if (!osDetectionInitialized.current) {
          osDetectionInitialized.current = true;
          setOSDetection(result.privileged && result.osDetection);
        }
      })
      .catch((requestError) => setError(messageFor(requestError)));
  }, []);

  useEffect(() => {
    const source = new EventSource("/api/scans/events");
    source.onmessage = (message) => {
      const event = JSON.parse(message.data) as ScanEvent;
      if (event.type === "scan" && event.scan) {
        setScans((current) => replaceScan(current, event.scan!));
      } else if (event.type === "host" && event.host && event.scanId) {
        const summary = summarizeHost(event.host);
        setHostPages((current) => ({
          ...current,
          [event.scanId!]: upsertHost(current[event.scanId!], summary),
        }));
      }
    };
    return () => source.close();
  }, []);

  useEffect(() => {
    setNavigationPrefix(undefined);
    setSelectedHost(undefined);
    setSelectedKey(undefined);
    setProgress(undefined);
    setScanTools({});
    if (!selectedID) {
      setSelected(undefined);
      setOutput("");
      setHosts(undefined);
      return;
    }

    let closed = false;
    const source = new EventSource(`/api/scans/${selectedID}/events`);
    void Promise.all([getScan(selectedID), listHosts(selectedID)])
      .then(([scan, page]) => {
        if (closed) return;
        setSelected(scan);
        setOutput(scan.output);
        setHosts(page);
        setHostPages((current) => ({ ...current, [scan.id]: page }));
      })
      .catch((requestError) => {
        if (!closed) setError(messageFor(requestError));
      });

    source.onmessage = (message) => {
      const event = JSON.parse(message.data) as ScanEvent;
      if (event.type === "scan" && event.scan) {
        setSelected(event.scan);
        setOutput(event.scan.output);
        setScans((current) => replaceScan(current, event.scan!));
        if (finalStatuses.has(event.scan.status)) {
          setProgress(undefined);
          source.close();
          void refreshHosts(event.scan.id);
          void refreshScans();
        }
      } else if (event.type === "output" && event.text) {
        setOutput((current) => current + event.text);
      } else if (event.type === "progress" && event.progress) {
        setProgress(event.progress);
      } else if (event.type === "tool" && event.tool) {
        setScanTools((current) => ({ ...current, [event.tool!.id]: event.tool! }));
      } else if (event.type === "host" && event.host) {
        const summary = summarizeHost(event.host);
        setHosts((current) => upsertHost(current, summary));
        setHostPages((current) => ({
          ...current,
          [selectedID]: upsertHost(current[selectedID], summary),
        }));
        setSelectedHost((current) => current?.id === event.host!.id ? event.host : current);
      }
    };
    source.onerror = () => {
      if (!closed) setError("The live observation stream was interrupted. Reconnecting…");
    };

    return () => {
      closed = true;
      source.close();
    };
  }, [refreshHosts, refreshScans, selectedID]);

  useEffect(() => {
    if (!selectedID || !capabilities?.toolActivity) return;
    let closed = false;
    void listTools(selectedID)
      .then((tools) => {
        if (closed) return;
        const persisted = Object.fromEntries(tools.map((tool) => [tool.id, tool]));
        setScanTools((current) => ({ ...persisted, ...current }));
      })
      .catch((requestError) => {
        if (!closed) setError(messageFor(requestError));
      });
    return () => { closed = true; };
  }, [capabilities?.toolActivity, selectedID]);

  useEffect(() => {
    if (sceneView === "selected" || scans.length === 0) return;
    let closed = false;
    const visible = sceneView === "recent"
      ? scans.slice(0, maximumRecentScans)
      : includedScanIDs === undefined ? scans : scans.filter((scan) => includedScanIDs.has(scan.id));
    void Promise.all(visible.map(async (scan) => [scan.id, await listHosts(scan.id)] as const))
      .then((entries) => {
        if (!closed) setHostPages((current) => ({ ...current, ...Object.fromEntries(entries) }));
      })
      .catch((requestError) => {
        if (!closed) setError(messageFor(requestError));
      });
    return () => { closed = true; };
  }, [includedScanIDs, scans, sceneView]);

  useEffect(() => {
    const missing = scans.filter((scan) => finalStatuses.has(scan.status) && hostPages[scan.id] === undefined && !loadingHostPages.current.has(scan.id));
    if (missing.length === 0) return;
    missing.forEach((scan) => loadingHostPages.current.add(scan.id));
    void Promise.all(missing.map(async (scan) => [scan.id, await listHosts(scan.id)] as const))
      .then((entries) => setHostPages((current) => ({ ...current, ...Object.fromEntries(entries) })))
      .catch((requestError) => setError(messageFor(requestError)))
      .finally(() => missing.forEach((scan) => loadingHostPages.current.delete(scan.id)));
  }, [hostPages, scans]);

  useEffect(() => {
    if (!selected || finalStatuses.has(selected.status)) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [selected]);

  useEffect(() => {
    outputRef.current?.scrollTo({ top: outputRef.current.scrollHeight });
  }, [output]);

  useEffect(() => {
    if (!helpOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setHelpOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [helpOpen]);

  useEffect(() => {
    window.localStorage.setItem("lantern-history-width", String(historyWidth));
  }, [historyWidth]);

  const scanSeries = useMemo<ScanSeries[]>(
    () => sortScanSeries(buildScanSeries(scans, hostPages), historySort),
    [historySort, hostPages, scans],
  );
  const includedScans = useMemo(
    () => includedScanIDs === undefined ? scans : scans.filter((scan) => includedScanIDs.has(scan.id)),
    [includedScanIDs, scans],
  );
  const includedScansActive = includedScans.some((scan) => scan.status === "queued" || scan.status === "running");
  const selectedActive = selected?.status === "queued" || selected?.status === "running";
  const allScopes = useMemo<SceneScope[]>(() => scans.map((scan) => ({
    id: scan.id,
    label: `${scan.target} · ${formatTimestamp(scan.createdAt)}`,
    target: scan.target,
    status: scan.status,
    hosts: (scan.id === selectedID ? hosts : hostPages[scan.id])?.items ?? [],
    routes: routeMaps[scan.id]?.routes,
  })), [hostPages, hosts, routeMaps, scans, selectedID]);
  const focusPrefix = useMemo<IPv4Prefix | undefined>(() => {
    if (!selected) return undefined;
    if (navigationPrefix && sceneView !== "selected" && sceneView !== "selection" && sceneView !== "recent") return navigationPrefix;
    if (sceneView === "all") return prefixForTarget(selected.target, 0);
    if (sceneView === "range8") return prefixForTarget(selected.target, 8);
    if (sceneView === "range16") return prefixForTarget(selected.target, 16);
    if (sceneView === "range24") return prefixForTarget(selected.target, 24);
    return undefined;
  }, [navigationPrefix, sceneView, selected]);
  const includedScopes = useMemo(
    () => includedScanIDs === undefined ? allScopes : allScopes.filter((scope) => includedScanIDs.has(scope.id)),
    [allScopes, includedScanIDs],
  );
  const sceneScopes = useMemo<SceneScope[]>(() => {
    if (sceneView === "selected") return allScopes.filter((scope) => scope.id === selectedID);
    if (sceneView === "selection") return includedScopes;
    if (sceneView === "recent") return allScopes.slice(0, maximumRecentScans);
    return focusPrefix ? includedScopes.filter((scope) => scopeIntersectsPrefix(scope, focusPrefix)) : [];
  }, [allScopes, focusPrefix, includedScopes, sceneView, selectedID]);
  const routeScopeKey = sceneScopes.map((scope) => `${scope.id}:${scope.hosts.length}:${scope.status}`).join("|");
  useEffect(() => {
    if (sceneStyle !== "map" || !capabilities?.routeMapping) return;
    const pending = sceneScopes.filter((scope) => scope.status === "completed" && !loadedRoutes.current.has(scope.id));
    if (pending.length === 0) return;
    pending.forEach((scope) => loadedRoutes.current.add(scope.id));
    void Promise.all(pending.map(async (scope) => {
      try {
        return { scope, routes: await listRoutes(scope.id) };
      } catch (requestError) {
        loadedRoutes.current.delete(scope.id);
        setError(messageFor(requestError));
        return undefined;
      }
    })).then((results) => {
      const loaded = results.filter((result): result is { scope: SceneScope; routes: RouteMap } => result !== undefined);
      setRouteMaps((current) => ({ ...current, ...Object.fromEntries(loaded.map((result) => [result.scope.id, result.routes])) }));
      const missing = loaded.filter((result) => result.routes.routes.length === 0).map((result) => result.scope);
      if (missing.length > 0) traceScopes(missing, routeScopeKey);
    });
  }, [capabilities?.routeMapping, routeScopeKey, sceneStyle]);

  function traceScopes(scopes: SceneScope[], scopeKey: string) {
    const jobs = [...new Map(scopes.flatMap((scope) => scope.hosts
      .filter((host) => host.state === "up" && host.address)
      .map((host) => [`${scope.id}:${host.address}`, { scanID: scope.id, target: host.address }] as const))).values()];
    if (jobs.length === 0) return;
    setRouteProgress({ scopeKey, completed: 0, total: jobs.length, failed: 0, tools: [] });
    let nextJob = 0;
    async function worker() {
      while (nextJob < jobs.length) {
        const job = jobs[nextJob++];
        let failed = false;
        let tool = "";
        try {
          const route = await mapRoute(job.scanID, job.target);
          failed = Boolean(route.error);
          tool = route.tool ?? "";
          setRouteMaps((current) => {
            const existing = current[job.scanID] ?? { tool: "", routes: [] };
            return {
              ...current,
              [job.scanID]: {
                tool: tool || existing.tool,
                routes: [...existing.routes.filter((item) => item.target !== route.target), route],
              },
            };
          });
        } catch (requestError) {
          failed = true;
          setError(messageFor(requestError));
        } finally {
          setRouteProgress((current) => current?.scopeKey === scopeKey ? {
            ...current,
            completed: current.completed + 1,
            failed: current.failed + (failed ? 1 : 0),
            tools: tool && !current.tools.includes(tool) ? [...current.tools, tool] : current.tools,
          } : current);
        }
      }
    }
    void Promise.all(Array.from({ length: Math.min(10, jobs.length) }, () => worker()));
  }
  const layoutPrefix = useMemo(() => {
    if (focusPrefix) return focusPrefix;
    if (sceneView === "recent" || sceneView === "selection") return commonPrefixForScopes(sceneScopes);
    if (selected && /\/32$/.test(selected.target)) return undefined;
    return selected ? prefixForTarget(selected.target, 24) : undefined;
  }, [focusPrefix, sceneScopes, sceneView, selected]);
  const scene = useMemo(() => buildSceneModel(sceneScopes, sceneStyle, layoutPrefix), [layoutPrefix, sceneScopes, sceneStyle]);
  const { focus: sceneFocus, groups, links, nodes, waypoints } = scene;
  const selectedNode = nodes.find((node) => node.key === selectedKey);
  const inspectedScan = selectedNode
    ? scans.find((scan) => scan.id === selectedNode.scanID)
    : selected;
  useEffect(() => {
    const address = selected ? singleAddressTarget(selected.target) : undefined;
    if (!selected || !address || selectedHost || !hosts?.items.length) return;
    const summary = hosts.items.find((host) => host.address.toLowerCase() === address.toLowerCase()) ?? hosts.items[0];
    const requestKey = `${selected.id}:${summary.id}`;
    if (autoHostRequest.current === requestKey) return;
    autoHostRequest.current = requestKey;
    const node = nodes.find((candidate) => candidate.scanID === selected.id && candidate.hostID === summary.id);
    if (node) setSelectedKey(node.key);
    void getHost(selected.id, summary.id)
      .then((host) => {
        if (autoHostRequest.current === requestKey) setSelectedHost(host);
      })
      .catch((requestError) => {
        if (autoHostRequest.current === requestKey) setError(messageFor(requestError));
      });
  }, [hosts, nodes, selected, selectedHost]);
  const sceneActive = sceneScopes.some((scope) => scope.status === "queued" || scope.status === "running");
  const observedCount = sceneScopes.reduce((total, scope) => total + scope.hosts.length, 0);
  const visibleRouteProgress = routeProgress?.scopeKey === routeScopeKey ? routeProgress : undefined;
  const routingActive = Boolean(visibleRouteProgress && visibleRouteProgress.completed < visibleRouteProgress.total);
  const routePercent = visibleRouteProgress ? (visibleRouteProgress.completed / visibleRouteProgress.total) * 100 : 0;
  const routeToolLabel = visibleRouteProgress?.tools.length
    ? visibleRouteProgress.tools.join(" + ")
    : capabilities?.routeTool || "route probe";
  const toolStatuses = Object.values(scanTools)
    .filter((tool) => !visibleRouteProgress || !tool.id.startsWith("route:"))
    .sort((left, right) => left.id === "nmap" ? -1 : right.id === "nmap" ? 1 : left.label.localeCompare(right.label));
  if (visibleRouteProgress) {
    toolStatuses.push({ id: "route-mapping", label: `Route mapping (${routeToolLabel})`, active: routingActive });
  }
  const activeProfile = profiles.find((profile) => profile.id === profileID);
  const isRangeView = sceneView.startsWith("range") || sceneView === "all";
  const fieldTitle = sceneView === "selected"
    ? selected?.target ?? "Observation"
    : sceneView === "recent"
      ? `${sceneScopes.length} recent observations`
      : sceneView === "selection"
      ? `${sceneScopes.length} selected observations`
      : focusPrefix?.label ?? "IPv4 range unavailable";
  const redoRouteScopes = includedScopes.filter((scope) => scope.status === "completed" && scope.hosts.some((host) => host.state === "up"));

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!target.trim()) return;
    setSubmitting(true);
    setError("");
    try {
      const selectedProfile = profiles.find((profile) => profile.id === profileID);
      const normalizedText = profileText.trim();
      let resolvedProfile = profiles.find((profile) => profile.argumentText === normalizedText);
      if (!resolvedProfile) {
        resolvedProfile = selectedProfile && !selectedProfile.builtIn
          ? await updateProfile(selectedProfile.id, normalizedText)
          : await createProfile(normalizedText);
        setProfiles((current) => upsertProfile(current, resolvedProfile!));
        setProfileID(resolvedProfile.id);
        setProfileText(resolvedProfile.argumentText);
      }
      const scan = await startScan(target.trim(), resolvedProfile.id, osDetection);
      setScans((current) => [scan, ...current]);
      setIncludedScanIDs(new Set([scan.id]));
      setSceneView("selected");
      setSelectedID(scan.id);
      setSelected(scan);
      setHosts({ items: [], total: 0, limit: 500, offset: 0 });
      setHostPages((current) => ({ ...current, [scan.id]: { items: [], total: 0, limit: 500, offset: 0 } }));
      setOutput("");
      setTarget("");
    } catch (requestError) {
      setError(messageFor(requestError));
    } finally {
      setSubmitting(false);
    }
  }

  function selectProfile(profile: ScanProfile) {
    setProfileID(profile.id);
    setProfileText(profile.argumentText);
    setProfilesOpen(false);
  }

  async function removeProfile() {
    const selectedProfile = profiles.find((profile) => profile.id === profileID);
    if (!selectedProfile || selectedProfile.builtIn) return;
    try {
      await deleteProfile(selectedProfile.id);
      const remaining = profiles.filter((profile) => profile.id !== selectedProfile.id);
      const fallback = remaining.find((profile) => profile.id === defaultProfileID) ?? remaining[0];
      setProfiles(remaining);
      setProfilesOpen(false);
      if (fallback) {
        setProfileID(fallback.id);
        setProfileText(fallback.argumentText);
      }
      setError("");
    } catch (requestError) {
      setError(messageFor(requestError));
    }
  }

  async function stop() {
    if (!selected) return;
    try {
      await cancelScan(selected.id);
    } catch (requestError) {
      setError(messageFor(requestError));
    }
  }

  async function rescan(scan: Scan) {
    if (bulkActionPending) return;
    setOpenScanMenu(undefined);
    setBulkActionPending(true);
    setError("");
    try {
      const nextScan = await startScan(scan.target, scan.profileId, scan.osDetection);
      setScans((current) => [nextScan, ...current]);
      setIncludedScanIDs(new Set([nextScan.id]));
      setSceneView("selected");
      setSelectedID(nextScan.id);
      setSelected(nextScan);
      setHosts({ items: [], total: 0, limit: 500, offset: 0 });
      setHostPages((current) => ({ ...current, [nextScan.id]: { items: [], total: 0, limit: 500, offset: 0 } }));
      setOutput("");
    } catch (requestError) {
      setError(messageFor(requestError));
    } finally {
      setBulkActionPending(false);
    }
  }

  async function removeScans(identifiers: string[]) {
    if (identifiers.length === 0) return;
    const description = identifiers.length === 1
      ? "this observation"
      : `these ${identifiers.length} observations`;
    if (!window.confirm(`Delete ${description}? This cannot be undone.`)) return;
    setOpenScanMenu(undefined);
    setBulkActionPending(true);
    try {
      await Promise.all(identifiers.map(deleteScan));
      const removed = new Set(identifiers);
      const remaining = scans.filter((scan) => !removed.has(scan.id));
      setScans(remaining);
      setIncludedScanIDs((current) => current === undefined ? current : new Set([...current].filter((id) => !removed.has(id))));
      setHostPages((current) => {
        const next = { ...current };
        identifiers.forEach((identifier) => delete next[identifier]);
        return next;
      });
      setRouteMaps((current) => {
        const next = { ...current };
        identifiers.forEach((identifier) => delete next[identifier]);
        return next;
      });
      identifiers.forEach((identifier) => loadedRoutes.current.delete(identifier));
      if (selectedID && removed.has(selectedID)) setSelectedID(remaining[0]?.id);
      setError("");
    } catch (requestError) {
      setError(messageFor(requestError));
    } finally {
      setBulkActionPending(false);
    }
  }

  async function refreshSelectedScans() {
    if (includedScans.length === 0) return;
    setOpenScanMenu(undefined);
    setBulkActionPending(true);
    try {
      const refreshed = await Promise.all(includedScans.map(async (scan) => ({
        scan: await getScan(scan.id),
        hosts: await listHosts(scan.id),
      })));
      const scansByID = new Map(refreshed.map((item) => [item.scan.id, item.scan]));
      const hostsByID = Object.fromEntries(refreshed.map((item) => [item.scan.id, item.hosts]));
      setScans((current) => current.map((scan) => scansByID.get(scan.id) ?? scan));
      setHostPages((current) => ({ ...current, ...hostsByID }));
      const current = selectedID ? refreshed.find((item) => item.scan.id === selectedID) : undefined;
      if (current) {
        setSelected(current.scan);
        setOutput(current.scan.output);
        setHosts(current.hosts);
      }
      setError("");
    } catch (requestError) {
      setError(messageFor(requestError));
    } finally {
      setBulkActionPending(false);
    }
  }

  async function selectNode(node: SceneNode) {
    setSelectedKey(node.key);
    if (node.hostID === undefined) {
      setSelectedHost(undefined);
      return;
    }
    try {
      setSelectedHost(await getHost(node.scanID, node.hostID));
    } catch (requestError) {
      setError(messageFor(requestError));
    }
  }

  function toggleScanInclusion(identifier: string) {
    const next = new Set(includedScanIDs ?? []);
    if (next.has(identifier)) next.delete(identifier);
    else next.add(identifier);
    applyScanSelection(next);
  }

  function toggleSeriesInclusion(series: ScanSeries) {
    const next = new Set(includedScanIDs ?? []);
    const identifiers = series.scans.map((scan) => scan.id);
    if (identifiers.every((identifier) => next.has(identifier))) identifiers.forEach((identifier) => next.delete(identifier));
    else identifiers.forEach((identifier) => next.add(identifier));
    applyScanSelection(next);
  }

  function toggleSeriesExpanded(key: string) {
    setExpandedSeries((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
    setOpenScanMenu(undefined);
  }

  function selectScanRow(identifier: string, event: ReactMouseEvent<HTMLButtonElement>) {
    setOpenScanMenu(undefined);
    setNavigationPrefix(undefined);
    if (event.shiftKey && selectedID) {
      const anchor = scans.findIndex((scan) => scan.id === selectedID);
      const targetIndex = scans.findIndex((scan) => scan.id === identifier);
      if (anchor >= 0 && targetIndex >= 0) {
        const [start, end] = anchor < targetIndex ? [anchor, targetIndex] : [targetIndex, anchor];
        setSelectedID(identifier);
        applyScanSelection(new Set(scans.slice(start, end + 1).map((scan) => scan.id)));
        return;
      }
    }
    if (event.metaKey || event.ctrlKey) {
      setSelectedID(identifier);
      toggleScanInclusion(identifier);
      return;
    }
    setSelectedID(identifier);
    setIncludedScanIDs(new Set([identifier]));
    setSceneView("selected");
  }

  function applyScanSelection(next: Set<string>) {
    setIncludedScanIDs(next);
    if (next.size === 1) {
      const only = next.values().next().value;
      if (only) setSelectedID(only);
      setSceneView("selected");
    } else {
      setSceneView("selection");
    }
  }

  function toggleAllScans() {
    applyScanSelection(includedScanIDs?.size === scans.length ? new Set() : new Set(scans.map((scan) => scan.id)));
  }

  function beginHistoryResize(event: ReactPointerEvent<HTMLDivElement>) {
    historyResize.current = { pointerID: event.pointerId, startX: event.clientX, startWidth: historyWidth };
    event.currentTarget.setPointerCapture(event.pointerId);
  }

  function continueHistoryResize(event: ReactPointerEvent<HTMLDivElement>) {
    const resize = historyResize.current;
    if (!resize || resize.pointerID !== event.pointerId) return;
    setHistoryWidth(clampHistoryWidth(resize.startWidth + event.clientX - resize.startX));
  }

  function endHistoryResize(event: ReactPointerEvent<HTMLDivElement>) {
    if (historyResize.current?.pointerID !== event.pointerId) return;
    historyResize.current = undefined;
    event.currentTarget.releasePointerCapture(event.pointerId);
  }

  function resizeHistoryWithKeyboard(event: ReactKeyboardEvent<HTMLDivElement>) {
    if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      event.preventDefault();
      setHistoryWidth((current) => clampHistoryWidth(current + (event.key === "ArrowLeft" ? -16 : 16)));
    } else if (event.key === "Home") {
      event.preventDefault();
      setHistoryWidth(minimumHistoryWidth);
    } else if (event.key === "End") {
      event.preventDefault();
      setHistoryWidth(maximumHistoryWidth);
    }
  }

  function enterPrefix(group: { prefix?: IPv4Prefix }) {
    if (!group.prefix) return;
    setNavigationPrefix(group.prefix);
    setSceneView(viewForPrefix(group.prefix.length));
  }

  return (
    <main className="lantern-app">
      <header className="topbar">
        <div className="brand"><span aria-hidden="true">L</span><strong>Lantern</strong></div>
        <form className="scan-form" onSubmit={submit}>
          <input
            className="target-input"
            aria-label="Hostname, IP, or CIDR"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="Hostname, IP, or CIDR"
            autoComplete="off"
            spellCheck={false}
          />
          <div className="profile-picker">
            <div className="profile-picker-heading">
              <button
                className="profile-picker-trigger"
                type="button"
                aria-haspopup="listbox"
                aria-expanded={profilesOpen}
                onClick={() => setProfilesOpen((current) => !current)}
              >
                <strong>{activeProfile?.builtIn ? activeProfile.label : "Custom"}</strong>
                <span aria-hidden="true">⌄</span>
              </button>
              <label
                className="os-toggle"
                title={capabilities?.osDetection ? "Add Nmap OS detection" : "Run Lantern with sudo to enable OS detection"}
              >
                <input
                  type="checkbox"
                  checked={osDetection}
                  disabled={!capabilities?.osDetection}
                  onChange={(event) => setOSDetection(event.target.checked)}
                />
                <span>OS</span>
              </label>
              {profiles.some((profile) => profile.id === profileID && !profile.builtIn) && (
                <button className="profile-delete" type="button" aria-label="Delete custom scan profile" onClick={() => void removeProfile()}>×</button>
              )}
            </div>
            <input
              aria-label="Nmap scan profile or arguments"
              value={profileText}
              onChange={(event) => setProfileText(event.target.value)}
              placeholder="Nmap arguments"
              autoComplete="off"
              spellCheck={false}
            />
            {profilesOpen && (
              <div className="profile-menu" role="listbox" aria-label="Scan profiles">
                {profiles.map((profile) => (
                  <button
                    type="button"
                    role="option"
                    aria-selected={profile.id === profileID}
                    onClick={() => selectProfile(profile)}
                    key={profile.id}
                  >
                    <strong>{profile.builtIn ? profile.label : "Custom"}</strong>
                    <code>{profile.argumentText}</code>
                  </button>
                ))}
              </div>
            )}
          </div>
          <button type="submit" disabled={submitting || !target.trim()}>
            {submitting ? "Starting…" : "Observe"}
          </button>
        </form>
        <div className="header-actions">
          <span className={`local-state ${capabilities?.privileged ? "privileged" : ""}`}><i /> {capabilities?.privileged ? "Privileged" : "Local"}</span>
          <button className="help-trigger" type="button" aria-label="Open help" aria-haspopup="dialog" onClick={() => setHelpOpen(true)}>?</button>
        </div>
      </header>

      {error && <div className="error-banner" role="alert">{error}</div>}

      {helpOpen && (
        <div className="help-backdrop" onMouseDown={() => setHelpOpen(false)}>
          <section className="help-dialog" role="dialog" aria-modal="true" aria-labelledby="help-title" onMouseDown={(event) => event.stopPropagation()}>
            <header>
              <div><span className="eyebrow">Lantern guide</span><h2 id="help-title">How to observe a network</h2></div>
              <button type="button" aria-label="Close help" autoFocus onClick={() => setHelpOpen(false)}>×</button>
            </header>
            <div className="help-content">
              <section><h3>Start a scan</h3><p>Enter a hostname, IP address, or CIDR range, choose a profile, then select <strong>Observe</strong>. Scans continue in the background, and you can start or inspect other scans while they run.</p></section>
              <section><h3>Profiles and OS detection</h3><p>Discovery finds hosts; Quick, Standard, and Deep collect progressively more service evidence. Edit the Nmap arguments to create a custom profile. OS detection requires privileged mode and defaults on when available.</p></section>
              <section><h3>History and time</h3><p>Use the boxes beside observations to include runs in the field. Selecting multiple runs creates a temporal view. Repeated hostname and IP targets are grouped when DNS or observed addresses show they are the same host.</p></section>
              <section><h3>Navigate the field</h3><p>Drag to orbit, scroll to zoom, and select a sphere for details. Range views move between /24, /16, and /8 address space. Map uses traceroute evidence when a supported route tool is installed.</p></section>
              <section><h3>Sphere colors</h3><p><i className="legend-web" /> Web service &nbsp; <i className="legend-none" /> No open ports &nbsp; <i className="legend-up" /> Other services &nbsp; <i className="legend-provisional" /> Discovered &nbsp; <i className="legend-pending" /> No response</p></section>
              <section><h3>Host evidence</h3><p>The right panel shows network ownership and location, OS fingerprints, TLS certificates, and exposed services. Web ports and hostnames open directly when a usable URL is available.</p></section>
            </div>
          </section>
        </div>
      )}

      <section className="app-grid" style={{ "--history-width": `${historyWidth}px` } as CSSProperties}>
        <aside className="history-rail">
          <div className="rail-heading">
            <span>Observations</span>
            <div className="rail-actions">
              <label className="select-all-scans">
                <input type="checkbox" checked={scans.length > 0 && includedScanIDs?.size === scans.length} onChange={toggleAllScans} />
                <span>All</span>
              </label>
              <button
                className="bulk-scan-menu-trigger"
                aria-label="Actions for selected scans"
                aria-haspopup="menu"
                aria-expanded={openScanMenu === "bulk"}
                disabled={scans.length === 0}
                onClick={() => setOpenScanMenu((current) => current === "bulk" ? undefined : "bulk")}
              >•••</button>
              {openScanMenu === "bulk" && (
                <div className="scan-menu bulk-scan-menu" role="menu">
                  <button role="menuitem" disabled={includedScans.length === 0 || bulkActionPending} onClick={() => void refreshSelectedScans()}>Refresh</button>
                  <button
                    role="menuitem"
                    title={includedScans.length === 1 ? "Run this scan again" : "Select one observation to rescan"}
                    disabled={includedScans.length !== 1 || bulkActionPending}
                    onClick={() => void rescan(includedScans[0])}
                  >Rescan</button>
                  <button className="danger" role="menuitem" disabled={includedScans.length === 0 || includedScansActive || bulkActionPending} onClick={() => void removeScans(includedScans.map((scan) => scan.id))}>Delete</button>
                </div>
              )}
            </div>
          </div>
          <div className="history-sort" aria-label="Sort observations">
            <span>Sort</span>
            {(["date", "name", "ip"] as const).map((sort) => (
              <button
                type="button"
                aria-pressed={historySort === sort}
                onClick={() => setHistorySort(sort)}
                key={sort}
              >{sort === "ip" ? "IP" : `${sort[0].toUpperCase()}${sort.slice(1)}`}</button>
            ))}
          </div>
          <div className="scan-list">
            {scanSeries.map((series) => {
              const latest = series.scans[0];
              const repeated = series.scans.length > 1;
              const mixedTargets = new Set(series.scans.map((scan) => normalizeScanTarget(scan.target))).size > 1;
              const expanded = expandedSeries.has(series.key);
              const includedCount = series.scans.filter((scan) => includedScanIDs?.has(scan.id) ?? true).length;
              const allIncluded = includedCount === series.scans.length;
              const seriesMenuKey = `series:${series.key}`;
              return (
                <div className={`scan-series ${expanded ? "expanded" : ""}`} key={series.key}>
                  <div className={`scan-row series-summary ${includedCount > 0 ? "included" : ""} ${selectedID === latest.id ? "selected" : ""}`}>
                    {repeated ? (
                      <button className="series-toggle" aria-label={`${expanded ? "Collapse" : "Expand"} ${series.target} history`} aria-expanded={expanded} onClick={() => toggleSeriesExpanded(series.key)}>›</button>
                    ) : <span className="series-toggle-spacer" />}
                    <label className="scan-inclusion" title="Include this observation history in multi-scan views">
                      <input
                        type="checkbox"
                        checked={allIncluded}
                        onChange={() => toggleSeriesInclusion(series)}
                        aria-label={`Include all observations of ${series.target} in multi-scan views`}
                      />
                      <i className={includedCount > 0 && !allIncluded ? "partial" : ""} aria-hidden="true" />
                    </label>
                    <button className="scan-select" onClick={(event) => selectScanRow(latest.id, event)}>
                      <i className={`scan-dot ${latest.status}`} />
                      <span>
                        <strong className="scan-title"><ScrollingScanName>{series.target}</ScrollingScanName>{repeated && <b className="series-count">×{series.scans.length}</b>}</strong>
                        <small>{formatTimestamp(latest.createdAt)}</small>
                      </span>
                    </button>
                    <button
                      className="scan-menu-trigger"
                      aria-label={`Options for ${series.target} history`}
                      aria-expanded={openScanMenu === seriesMenuKey}
                      onClick={() => setOpenScanMenu((current) => current === seriesMenuKey ? undefined : seriesMenuKey)}
                    >•••</button>
                    {openScanMenu === seriesMenuKey && (
                      <div className="scan-menu">
                        <button disabled={bulkActionPending} onClick={() => void rescan(latest)}>Rescan</button>
                        <button className="danger" disabled={series.scans.some((scan) => scan.status === "queued" || scan.status === "running") || bulkActionPending} onClick={() => void removeScans(series.scans.map((scan) => scan.id))}>Delete {repeated ? "history" : ""}</button>
                      </div>
                    )}
                  </div>
                  {repeated && expanded && (
                    <div className="series-runs">
                      {series.scans.map((scan, index) => (
                        <div className={`scan-row series-run ${includedScanIDs?.has(scan.id) ? "included" : ""} ${selectedID === scan.id ? "selected" : ""}`} key={scan.id}>
                          <label className="scan-inclusion" title="Include this run in multi-scan views">
                            <input type="checkbox" checked={includedScanIDs?.has(scan.id) ?? true} onChange={() => toggleScanInclusion(scan.id)} aria-label={`Include ${scan.target} observation from ${formatTimestamp(scan.createdAt)}`} />
                            <i aria-hidden="true" />
                          </label>
                          <button className="scan-select" onClick={(event) => selectScanRow(scan.id, event)}>
                            <i className={`scan-dot ${scan.status}`} />
                            <span><strong>{mixedTargets ? scan.target : index === 0 ? "Latest run" : `Run ${series.scans.length - index}`}</strong><small>{formatTimestamp(scan.createdAt)}</small></span>
                          </button>
                          <button className="scan-menu-trigger" aria-label={`Options for ${formatTimestamp(scan.createdAt)} run`} aria-expanded={openScanMenu === scan.id} onClick={() => setOpenScanMenu((current) => current === scan.id ? undefined : scan.id)}>•••</button>
                          {openScanMenu === scan.id && (
                            <div className="scan-menu">
                              <button disabled={bulkActionPending} onClick={() => void rescan(scan)}>Rescan</button>
                              <button className="danger" disabled={scan.status === "queued" || scan.status === "running" || bulkActionPending} onClick={() => void removeScans([scan.id])}>Delete</button>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
            {scans.length === 0 && <p className="empty-copy">No observations yet.</p>}
          </div>
          <div
            className="history-resizer"
            role="separator"
            aria-label="Resize observation history"
            aria-orientation="vertical"
            aria-valuemin={minimumHistoryWidth}
            aria-valuemax={maximumHistoryWidth}
            aria-valuenow={historyWidth}
            tabIndex={0}
            onDoubleClick={() => setHistoryWidth(defaultHistoryWidth)}
            onKeyDown={resizeHistoryWithKeyboard}
            onPointerDown={beginHistoryResize}
            onPointerMove={continueHistoryResize}
            onPointerUp={endHistoryResize}
            onPointerCancel={endHistoryResize}
          />
        </aside>

        <section className="field-panel">
          {selected ? (
            <>
              <div className="field-heading">
                <div>
                  <span className="eyebrow">{sceneStyle === "map" ? "Route topology" : isRangeView ? "Nested address space" : sceneView === "recent" || sceneView === "selection" ? "Multi-scan field" : "Observation field"}</span>
                  <h1>{fieldTitle}</h1>
                </div>
                <div className="field-controls">
                  <label className="style-picker">
                    <span>View</span>
                    <select value={sceneView} onChange={(event) => { setNavigationPrefix(undefined); setSceneView(event.target.value as SceneView); }}>
                      <option value="selected">Selected scan</option>
                      <option value="selection">Selected scans</option>
                      <option value="recent">Recent scans</option>
                      <option value="range24">Selected /24</option>
                      <option value="range16">Selected /16</option>
                      <option value="range8">Selected /8</option>
                      <option value="all">All loaded IPv4</option>
                    </select>
                  </label>
                  <label className="style-picker" title={!capabilities?.routeMapping ? capabilities?.routeMappingReason : undefined}>
                    <span>Style</span>
                    <select value={sceneStyle} onChange={(event) => setSceneStyle(event.target.value as SceneStyle)}>
                      {sceneStyleOptions.map((option) => (
                        <option value={option.value} disabled={option.value === "map" && capabilities !== undefined && !capabilities.routeMapping} key={option.value}>
                          {option.value === "map" && capabilities !== undefined && !capabilities.routeMapping
                            ? "Map — install mtr or traceroute"
                            : option.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  {sceneStyle === "map" && capabilities?.routeMapping && (
                    <button
                      className="route-redo"
                      type="button"
                      disabled={routingActive || redoRouteScopes.length === 0}
                      title="Re-run route probes for the selected scans, preferring mtr with traceroute fallback"
                      onClick={() => traceScopes(redoRouteScopes, routeScopeKey)}
                    >Redo traceroute</button>
                  )}
                  <div className="run-state">
                    {selectedActive && <span className="scan-wave"><i /><i /><i /></span>}
                    <span className={`status-pill ${selected.status}`}>{selected.status}</span>
                    {selectedActive && <button onClick={() => void stop()}>Cancel</button>}
                  </div>
                </div>
              </div>

              <div className="scene-stage">
                <Suspense fallback={<div className="scene-loading">Preparing the observation field…</div>}>
                  <NetworkScene active={sceneActive} focus={sceneFocus} groups={groups} links={links} nodes={nodes} waypoints={waypoints} style={sceneStyle} selectedKey={selectedKey} onEnterGroup={enterPrefix} onSelect={(node) => void selectNode(node)} />
                </Suspense>
                <div className="scene-metrics">
                  <div><span>Elapsed</span><strong>{formatElapsed(selected, now)}</strong></div>
                  <div><span>Observed</span><strong>{observedCount}</strong></div>
                  <div><span>Scope</span><strong>{isRangeView ? focusPrefix?.label : sceneView === "recent" || sceneView === "selection" ? `${sceneScopes.length} scans` : selected.hostsTotal || scopeSize(selected.target) || "—"}</strong></div>
                  <div><span>Phase</span><strong>{routingActive ? "Tracing routes" : isRangeView ? `${sceneScopes.length} scan${sceneScopes.length === 1 ? "" : "s"}` : sceneView === "recent" || sceneView === "selection" ? "Multi-scan" : selectedActive ? `Nmap · ${progress?.task || "Scanning"}` : "Final"}</strong></div>
                </div>
                {toolStatuses.length > 0 && (
                  <aside className="tool-status-panel" aria-label="Tool execution history">
                    <span>Tool activity</span>
                    <ul>
                      {toolStatuses.map((tool) => (
                        <li key={tool.id}>
                          <i className={tool.active ? "running" : "completed"} aria-hidden="true" />
                          <strong>{tool.label}</strong>
                          <small>{tool.active ? "Running" : "Completed"}</small>
                        </li>
                      ))}
                    </ul>
                  </aside>
                )}
                {(selectedActive || routingActive) && (
                  <div className={`scan-progress ${routingActive ? "route-progress" : ""}`}>
                    <span style={{ width: `${routingActive ? routePercent : boundedPercent(progress?.percent)}%` }} />
                    <p>{routingActive && visibleRouteProgress
                      ? `${routeToolLabel} · tracing routes · ${visibleRouteProgress.completed}/${visibleRouteProgress.total} hosts${visibleRouteProgress.failed ? ` · ${visibleRouteProgress.failed} failed` : ""}`
                      : <>Nmap · {progress?.task || "Scanning"}{progress?.percent ? ` · ${progress.percent}%` : ""}{progress?.remaining ? ` · about ${progress.remaining}s remaining` : ""}</>}</p>
                  </div>
                )}
              </div>

              <details className="diagnostics" open={selected.status === "failed"}>
                <summary>Process evidence</summary>
                <pre ref={outputRef}>{output || "Waiting for Nmap diagnostics…"}</pre>
              </details>
            </>
          ) : (
            <div className="welcome-state"><span>◌</span><h1>Begin an observation</h1><p>Enter a host or network above to build its field.</p></div>
          )}
        </section>

        <aside className="inspector">
          {selectedHost && inspectedScan ? <HostInspector host={selectedHost} scan={inspectedScan} scanLabel={selectedNode?.scanLabel} /> : selectedNode ? (
            <div className="inspector-empty">
              <span className="eyebrow">Address in scope</span>
              <h2>{selectedNode.address}</h2>
              <p>{selectedNode.scanLabel}</p>
              <p>{addressCoverageMessage(inspectedScan)}</p>
              {inspectedScan && <ScanCoverageCard scan={inspectedScan} addressState={addressCoverageState(inspectedScan)} coverageKind={inspectedScan.status === "completed" ? "no-response" : "unconfirmed"} />}
            </div>
          ) : selected ? (
            <div className="inspector-empty scope-inspector">
              <span className="eyebrow">Observation scope</span>
              <h2>{sceneView === "selected" ? selected.target : fieldTitle}</h2>
              <p>{nodes.length > 0
                ? `${observedCount} observed host${observedCount === 1 ? "" : "s"} across ${nodes.length} represented address slot${nodes.length === 1 ? "" : "s"}. Select a point to inspect its evidence and exposed services.`
                : "Zoom into a prefix sphere to reach its address and host layer."}</p>
              {selected.ownership && <OwnershipCard ownership={selected.ownership} />}
            </div>
          ) : null}
        </aside>
      </section>
    </main>
  );
}

function ScrollingScanName({ children }: { children: string }) {
  const viewport = useRef<HTMLSpanElement>(null);
  const content = useRef<HTMLSpanElement>(null);
  const [overflow, setOverflow] = useState(0);

  useEffect(() => {
    const viewportElement = viewport.current;
    const contentElement = content.current;
    if (!viewportElement || !contentElement) return;
    const measure = () => setOverflow(Math.max(0, Math.ceil(contentElement.scrollWidth - viewportElement.clientWidth)));
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(viewportElement);
    observer.observe(contentElement);
    return () => observer.disconnect();
  }, [children]);

  const duration = Math.min(30, Math.max(12, 10 + overflow / 10));
  const style = overflow > 0
    ? { "--scan-name-pan": `${-overflow}px`, "--scan-name-duration": `${duration}s` } as CSSProperties
    : undefined;
  return (
    <span className={`scan-name ${overflow > 0 ? "overflowing" : ""}`} ref={viewport} title={children}>
      <span ref={content} style={style}>{children}</span>
    </span>
  );
}

function HostInspector({ host, scan, scanLabel }: { host: HostObservation; scan: Scan; scanLabel?: string }) {
  const vendor = host.addresses.find((address) => address.vendor)?.vendor;
  const hostURL = preferredWebURL(host);
  const advertisements = (host.evidence ?? []).flatMap((evidence) => {
    const advertisement = serviceAdvertisement(evidence);
    return advertisement ? [{ evidence, advertisement }] : [];
  });
  const certificates = (host.evidence ?? []).flatMap((evidence) => {
    const result = tlsCertificateResult(evidence);
    return result ? [{ evidence, result }] : [];
  });
  return (
    <div className="host-inspector">
      <span className="eyebrow">Host observation</span>
      <h2>{hostURL
        ? <a href={hostURL} target="_blank" rel="noreferrer">{host.hostnames[0]?.name || primaryAddress(host)}</a>
        : host.hostnames[0]?.name || primaryAddress(host)}</h2>
      <p className="host-addresses">{host.addresses.map((address) => address.address).join(" · ")}</p>
      {scanLabel && <p className="host-scan-label">{scanLabel}</p>}
      <div className="host-badges">
        <span>{host.provisional ? "discovered" : host.state}</span>
        {vendor && <span>{vendor}</span>}
      </div>
      {host.ownership && <OwnershipCard ownership={host.ownership} />}
      {host.osStatus && (
        <section className={`os-card ${host.osStatus}`} aria-label="Operating system detection">
          <span>Operating system</span>
          {host.osStatus === "matched" && host.osMatches?.length ? (
            <>
              <strong>{host.osMatches[0].name}</strong>
              <small>{[
                `${host.osMatches[0].accuracy}% confidence`,
                host.osMatches[0].classes?.[0]?.vendor,
                host.osMatches[0].classes?.[0]?.family,
                host.osMatches[0].classes?.[0]?.generation,
                host.osMatches[0].classes?.[0]?.type,
              ].filter(Boolean).join(" · ")}</small>
              {host.osMatches.slice(1, 3).map((match) => <em key={`${match.name}-${match.accuracy}`}>{match.name} · {match.accuracy}%</em>)}
            </>
          ) : (
            <small>No conclusive OS fingerprint was returned.</small>
          )}
        </section>
      )}
      {certificates.length > 0 && <CertificateCard certificates={certificates} />}
      <div className="services-heading"><span>Services</span><b>{host.ports.filter((port) => port.state === "open").length} open</b></div>
      <div className="service-list">
        {host.ports.map((port) => {
          const portURL = webURL(host, port.number, port.protocol, port.state);
          return (
            <div className="service-row" key={`${port.protocol}-${port.number}`}>
              <code>{portURL
                ? <a href={portURL} target="_blank" rel="noreferrer">{port.number}/{port.protocol}</a>
                : <>{port.number}/{port.protocol}</>}</code>
              <div><strong>{serviceName(port.service, port.tunnel)}</strong><small>{[port.product, port.version, port.extraInfo].filter(Boolean).join(" ") || port.state}</small></div>
              <i className={port.state}>{port.state}</i>
            </div>
          );
        })}
        {host.ports.length === 0 && <p className="empty-copy">{host.provisional ? "Service scan still in progress." : "No interesting ports reported."}</p>}
      </div>
      <ScanCoverageCard
        scan={scan}
        addressState={host.provisional ? "Discovered; scan in progress" : host.state === "up" ? "Responded" : "Reported down"}
        coverageKind={host.provisional ? "unconfirmed" : "observed"}
      />
      {advertisements.length > 0 && (
        <>
          <div className="services-heading"><span>Advertisements</span><b>{advertisements.length} found</b></div>
          <div className="service-list advertised-services">
            {advertisements.map(({ evidence, advertisement }) => (
              <div className="service-row" key={evidence.id}>
                <code>{advertisement.port}/{advertisement.serviceType.endsWith("._udp") ? "udp" : "tcp"}</code>
                <div><strong>{advertisement.instance}</strong><small>{advertisement.serviceType} · {advertisement.hostname}</small></div>
                <i>{evidence.provider}</i>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

type CoverageKind = "observed" | "no-response" | "unconfirmed";

function ScanCoverageCard({ scan, addressState, coverageKind }: { scan: Scan; addressState: string; coverageKind: CoverageKind }) {
  const details = scanCoverage(scan, coverageKind);
  return (
    <section className="coverage-card" aria-label="Scan coverage">
      <span>Scan coverage</span>
      <dl>
        <div><dt>Run</dt><dd>{details.run}</dd></div>
        <div><dt>Address</dt><dd>{addressState}</dd></div>
        <div><dt>Ports</dt><dd>{details.ports}</dd></div>
        <div><dt>Services</dt><dd>{details.services}</dd></div>
        <div><dt>OS</dt><dd>{details.os}</dd></div>
      </dl>
    </section>
  );
}

function scanCoverage(scan: Scan, coverageKind: CoverageKind): { run: string; ports: string; services: string; os: string } {
  const args = scan.arguments;
  const run = scan.status === "completed"
    ? "Complete"
    : scan.status === "running"
      ? "In progress"
      : scan.status === "queued"
        ? "Queued"
        : `Partial — ${scan.status}`;
  const topPorts = argumentValue(args, "--top-ports");
  const selectedPorts = argumentValue(args, "-p");
  const protocol = args.includes("-sU") ? (args.some((arg) => arg === "-sT" || arg === "-sS") ? "TCP + UDP" : "UDP") : "TCP";
  const plannedPorts = args.includes("-sn")
    ? "Not tested — discovery only"
    : args.includes("-p-")
      ? `All ${protocol} ports`
      : topPorts
        ? `Top ${topPorts} ${protocol} ports`
        : selectedPorts
          ? `Selected ${protocol} ports: ${selectedPorts}`
          : `Nmap default ${protocol} ports`;
  const plannedServices = !args.includes("-sV")
    ? "Not performed"
    : args.includes("--version-light")
      ? "Light detection"
      : args.includes("--version-all")
        ? "Full detection"
        : "Standard detection";
  const plannedOS = scan.osDetection || args.includes("-O") ? "Performed" : "Not performed";
  if (coverageKind === "observed") return { run, ports: plannedPorts, services: plannedServices, os: plannedOS };
  if (coverageKind === "no-response") return { run, ports: "Not tested — no host response", services: "Not performed", os: "Not performed" };
  return {
    run,
    ports: plannedPorts.startsWith("Not tested") ? plannedPorts : `Planned: ${lowercaseFirst(plannedPorts)}`,
    services: plannedServices === "Not performed" ? plannedServices : `Planned: ${lowercaseFirst(plannedServices)}`,
    os: plannedOS === "Performed" ? "Planned" : plannedOS,
  };
}

function lowercaseFirst(value: string): string {
  return value ? value[0].toLowerCase() + value.slice(1) : value;
}

function argumentValue(args: string[], name: string): string | undefined {
  const separate = args.indexOf(name);
  if (separate >= 0) return args[separate + 1];
  return args.find((arg) => arg.startsWith(`${name}=`))?.slice(name.length + 1)
    ?? (name === "-p" ? args.find((arg) => arg.startsWith("-p") && arg !== "-p-")?.slice(2) : undefined);
}

function addressCoverageState(scan: Scan): string {
  if (scan.status === "completed") return "No response observed";
  if (scan.status === "running" || scan.status === "queued") return "Pending";
  return "Unknown — run incomplete";
}

function addressCoverageMessage(scan?: Scan): string {
  if (!scan) return "Coverage information is unavailable.";
  if (scan.status === "completed") return "No response was observed during this completed run.";
  if (scan.status === "running" || scan.status === "queued") return "Waiting for evidence from the active scan.";
  return "The run ended before Lantern could confirm whether this address was checked.";
}

interface AdvertisedService {
  instance: string;
  serviceType: string;
  hostname: string;
  port: number;
}

interface TLSCertificateEvidence {
  port: number;
  dnsNames: string[];
  commonName?: string;
  ipAddresses: string[];
  fingerprintSha256: string;
  notBefore: string;
  notAfter: string;
  verificationName: string;
  verified: boolean;
  verificationError?: string;
}

interface TLSCertificateFailureEvidence {
  port: number;
  error: string;
}

type TLSCertificateResult =
  | { kind: "certificate"; certificate: TLSCertificateEvidence }
  | { kind: "failure"; failure: TLSCertificateFailureEvidence };

function CertificateCard({ certificates }: { certificates: { evidence: ProviderEvidence; result: TLSCertificateResult }[] }) {
  return (
    <section className="certificate-card" aria-label="TLS certificates">
      <header><span>TLS certificates</span><b>{certificates.length}</b></header>
      {certificates.map(({ evidence, result }) => {
        if (result.kind === "failure") return (
          <div className="certificate-record" key={evidence.id}>
            <div className="certificate-title">
              <strong>{result.failure.port}/tcp</strong>
              <i className="unverified">Handshake failed</i>
            </div>
            <dl><div><dt>Error</dt><dd>{result.failure.error}</dd></div></dl>
          </div>
        );
        const certificate = result.certificate;
        const names = [...certificate.dnsNames, ...certificate.ipAddresses];
        return (
          <div className="certificate-record" key={evidence.id}>
            <div className="certificate-title">
              <strong>{certificate.port}/tcp</strong>
              <i className={certificate.verified ? "verified" : "unverified"}>{certificate.verified ? "Verified" : "Unverified"}</i>
            </div>
            <dl>
              {names.length > 0 && <div><dt>Names</dt><dd>{names.join(" · ")}</dd></div>}
              {certificate.commonName && !certificate.dnsNames.some((name) => name.toLowerCase() === certificate.commonName?.toLowerCase()) && (
                <div><dt>Common</dt><dd>{certificate.commonName}</dd></div>
              )}
              <div><dt>Valid</dt><dd>{formatCertificateDate(certificate.notBefore)} – {formatCertificateDate(certificate.notAfter)}</dd></div>
              <div><dt>SHA-256</dt><dd className="certificate-fingerprint">{certificate.fingerprintSha256}</dd></div>
              <div><dt>Verify</dt><dd>{certificate.verified
                ? certificate.verificationName
                : certificate.verificationError || `Failed for ${certificate.verificationName}`}</dd></div>
            </dl>
          </div>
        );
      })}
    </section>
  );
}

function serviceAdvertisement(evidence: ProviderEvidence): AdvertisedService | undefined {
  if (!evidence || evidence.kind !== "service.advertisement") return undefined;
  const payload = evidence.payload;
  if (typeof payload.instance !== "string" || typeof payload.serviceType !== "string" || typeof payload.hostname !== "string" || typeof payload.port !== "number") return undefined;
  return { instance: payload.instance, serviceType: payload.serviceType, hostname: payload.hostname, port: payload.port };
}

function tlsCertificateResult(evidence: ProviderEvidence): TLSCertificateResult | undefined {
  if (!evidence || (evidence.kind !== "tls.certificate" && evidence.kind !== "tls.certificate.failure")) return undefined;
  const payload = evidence.payload;
  if (evidence.kind === "tls.certificate.failure") {
    if (typeof payload.port !== "number" || typeof payload.error !== "string") return undefined;
    return { kind: "failure", failure: { port: payload.port, error: payload.error } };
  }
  if (
    typeof payload.port !== "number" ||
    !Array.isArray(payload.dnsNames) || !payload.dnsNames.every((name) => typeof name === "string") ||
    typeof payload.fingerprintSha256 !== "string" ||
    typeof payload.notBefore !== "string" || typeof payload.notAfter !== "string" ||
    typeof payload.verificationName !== "string" || typeof payload.verified !== "boolean"
  ) return undefined;
  const ipAddresses = Array.isArray(payload.ipAddresses)
    ? payload.ipAddresses.filter((address): address is string => typeof address === "string")
    : [];
  return { kind: "certificate", certificate: {
    port: payload.port,
    dnsNames: payload.dnsNames,
    commonName: typeof payload.commonName === "string" ? payload.commonName : undefined,
    ipAddresses,
    fingerprintSha256: payload.fingerprintSha256,
    notBefore: payload.notBefore,
    notAfter: payload.notAfter,
    verificationName: payload.verificationName,
    verified: payload.verified,
    verificationError: typeof payload.verificationError === "string" ? payload.verificationError : undefined,
  } };
}

function OwnershipCard({ ownership }: { ownership: Ownership }) {
  const headline = ownership.organization || ownership.networkName || ownership.cidr || ownership.range;
  const details = [
    ["Network", ownership.networkName !== headline ? ownership.networkName : undefined],
    ["CIDR", ownership.cidr],
    ["Range", ownership.range !== ownership.cidr ? ownership.range : undefined],
    ["Location", ownershipLocation(ownership)],
    ["Origin", ownership.origin],
    ["Sources", ownership.sources?.map(formatNetworkProfileSource).join(" + ")],
  ].filter((detail): detail is [string, string] => Boolean(detail[1]));
  return (
    <section className="ownership-card" aria-label="Network profile">
      <span>Network profile</span>
      {headline && <strong>{headline}</strong>}
      {details.length > 0 && <dl>{details.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>}
    </section>
  );
}

function ownershipLocation(ownership: Ownership): string | undefined {
  const location = [ownership.city, ownership.region, formatCountry(ownership.country)].filter(Boolean).join(", ");
  return location || undefined;
}

function formatCountry(country?: string): string | undefined {
  const value = country?.trim();
  if (!value || !/^[a-z]{2}$/i.test(value)) return value;

  try {
    return new Intl.DisplayNames(navigator.languages, { type: "region" }).of(value.toUpperCase()) ?? value;
  } catch {
    return value;
  }
}

function formatNetworkProfileSource(source: string): string {
  return source.toLowerCase() === "rdap" ? "RDAP" : source.toLowerCase() === "whois" ? "WHOIS" : source;
}

function summarizeHost(host: HostObservation): HostSummary {
  const primary = host.addresses.find((item) => item.type === "ipv4")
    ?? host.addresses.find((item) => item.type === "ipv6")
    ?? host.addresses[0];
  return {
    id: host.id,
    state: host.state,
    address: primary?.address ?? "",
    addressType: primary?.type ?? "",
    vendor: host.addresses.find((item) => item.vendor)?.vendor,
    hostname: host.hostnames[0]?.name,
    openPortCount: host.ports.filter((port) => port.state === "open").length,
    webAvailable: host.ports.some((port) => port.protocol === "tcp" && port.state === "open" && (port.number === 80 || port.number === 443)),
    provisional: host.provisional,
  };
}

function upsertHost(page: HostPage | undefined, host: HostSummary): HostPage {
  const current = page ?? { items: [], total: 0, limit: 500, offset: 0 };
  const exists = current.items.some((item) => item.id === host.id || item.address === host.address);
  return {
    ...current,
    total: exists ? current.total : current.total + 1,
    items: exists
      ? current.items.map((item) => item.id === host.id || item.address === host.address ? host : item)
      : [...current.items, host],
  };
}

function primaryAddress(host: HostObservation): string {
  return host.addresses.find((item) => item.type === "ipv4")?.address
    ?? host.addresses.find((item) => item.type === "ipv6")?.address
    ?? host.addresses[0]?.address
    ?? "Unknown host";
}

function preferredWebURL(host: HostObservation): string | undefined {
  const port = host.ports.find((item) => item.number === 443 && item.protocol === "tcp" && item.state === "open")
    ?? host.ports.find((item) => item.number === 80 && item.protocol === "tcp" && item.state === "open");
  return port && webURL(host, port.number, port.protocol, port.state);
}

function webURL(host: HostObservation, port: number, protocol: string, state: string): string | undefined {
  if (protocol !== "tcp" || state !== "open" || (port !== 443 && port !== 80)) return undefined;
  const address = primaryAddress(host);
  if (address === "Unknown host") return undefined;
  const authority = address.includes(":") ? `[${address}]` : address;
  return `${port === 443 ? "https" : "http"}://${authority}:${port}`;
}

function serviceName(service?: string, tunnel?: string): string {
  if (!service) return "Unknown";
  return tunnel ? `${tunnel}/${service}` : service;
}

function replaceScan(scans: Scan[], replacement: Scan): Scan[] {
  return scans.some((scan) => scan.id === replacement.id)
    ? scans.map((scan) => scan.id === replacement.id ? replacement : scan)
    : [replacement, ...scans];
}

function upsertProfile(profiles: ScanProfile[], replacement: ScanProfile): ScanProfile[] {
  return profiles.some((profile) => profile.id === replacement.id)
    ? profiles.map((profile) => profile.id === replacement.id ? replacement : profile)
    : [...profiles, replacement];
}

function messageFor(error: unknown): string {
  return error instanceof Error ? error.message : "Something went wrong";
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value));
}

function formatCertificateDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" }).format(date);
}

function normalizeScanTarget(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, "").replace(/\/(?:32|128)$/, "");
}

function clampHistoryWidth(value: number): number {
  return Math.min(maximumHistoryWidth, Math.max(minimumHistoryWidth, Math.round(value)));
}

function storedHistoryWidth(): number {
  const value = Number(window.localStorage.getItem("lantern-history-width"));
  return Number.isFinite(value) && value > 0 ? clampHistoryWidth(value) : defaultHistoryWidth;
}

function buildScanSeries(scans: Scan[], pages: Record<string, HostPage>): ScanSeries[] {
  const parents = scans.map((_, index) => index);
  const ownerByIdentity = new Map<string, number>();
  const find = (index: number): number => {
    while (parents[index] !== index) {
      parents[index] = parents[parents[index]];
      index = parents[index];
    }
    return index;
  };
  const union = (left: number, right: number) => {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot !== rightRoot) parents[rightRoot] = leftRoot;
  };

  scans.forEach((scan, index) => {
    for (const identity of scanIdentities(scan, pages[scan.id])) {
      const owner = ownerByIdentity.get(identity);
      if (owner === undefined) ownerByIdentity.set(identity, index);
      else union(owner, index);
    }
  });

  scans.forEach((scan, blockIndex) => {
    const block = ipv4ScanScope(scan.target);
    if (!block || !scan.target.includes("/") || block.prefix === 32) return;
    scans.forEach((candidate, candidateIndex) => {
      if (candidateIndex === blockIndex) return;
      const candidateScopes = ipv4CandidateScopes(candidate, pages[candidate.id]);
      if (candidateScopes.some((scope) => block.base <= scope.base && block.end >= scope.end)) {
        union(blockIndex, candidateIndex);
      }
    });
  });

  const grouped = new Map<number, Scan[]>();
  scans.forEach((scan, index) => {
    const root = find(index);
    const group = grouped.get(root);
    if (group) group.push(scan);
    else grouped.set(root, [scan]);
  });
  return [...grouped.values()].map((group) => {
    const blockScan = group
      .filter((scan) => scan.target.includes("/"))
      .map((scan) => ({ scan, scope: ipv4ScanScope(scan.target) }))
      .filter((item): item is { scan: Scan; scope: IPv4ScanScope } => item.scope !== undefined)
      .sort((left, right) => left.scope.prefix - right.scope.prefix || new Date(right.scan.createdAt).getTime() - new Date(left.scan.createdAt).getTime())[0]?.scan;
    const hostnameTarget = group.find((scan) => !isLiteralAddress(scan.target) && !scan.target.includes("/"));
    const reverseName = group.flatMap((scan) => pages[scan.id]?.items ?? [])
      .find((host) => host.hostname)?.hostname;
    const target = blockScan?.target ?? hostnameTarget?.target ?? reverseName ?? group[0].target;
    const address = group.flatMap((scan) => pages[scan.id]?.items ?? [])
      .find((host) => host.address)?.address
      ?? group.map((scan) => scan.target.replace(/^\[|\]$/g, "").replace(/\/\d+$/, ""))
        .find((candidate) => isLiteralAddress(candidate));
    const orderedScans = blockScan
      ? [blockScan, ...group.filter((scan) => scan.id !== blockScan.id)]
      : group;
    return { key: normalizeScanTarget(target), target, address, scans: orderedScans };
  });
}

interface IPv4ScanScope {
  base: number;
  end: number;
  prefix: number;
}

function ipv4ScanScope(target: string): IPv4ScanScope | undefined {
  const match = target.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
  if (!match) return undefined;
  const octets = match[1].split(".").map(Number);
  const prefix = match[2] === undefined ? 32 : Number(match[2]);
  if (octets.some((octet) => octet < 0 || octet > 255) || prefix < 0 || prefix > 32) return undefined;
  const address = octets.reduce((value, octet) => value * 256 + octet, 0);
  const size = 2 ** (32 - prefix);
  const base = Math.floor(address / size) * size;
  return { base, end: base + size - 1, prefix };
}

function ipv4CandidateScopes(scan: Scan, page?: HostPage): IPv4ScanScope[] {
  const targetScope = ipv4ScanScope(scan.target);
  if (targetScope) return [targetScope];
  return (page?.items ?? [])
    .map((host) => ipv4ScanScope(host.address))
    .filter((scope): scope is IPv4ScanScope => scope !== undefined);
}

function sortScanSeries(series: ScanSeries[], sort: HistorySort): ScanSeries[] {
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
  return [...series].sort((left, right) => {
    if (sort === "name") {
      return collator.compare(left.target, right.target) || newestFirst(left, right);
    }
    if (sort === "ip") {
      if (left.address && right.address) {
        return collator.compare(left.address, right.address) || collator.compare(left.target, right.target);
      }
      if (left.address) return -1;
      if (right.address) return 1;
    }
    return newestFirst(left, right) || collator.compare(left.target, right.target);
  });
}

function newestFirst(left: ScanSeries, right: ScanSeries): number {
  return new Date(right.scans[0].createdAt).getTime() - new Date(left.scans[0].createdAt).getTime();
}

function scanIdentities(scan: Scan, page?: HostPage): Set<string> {
  const normalizedTarget = normalizeScanTarget(scan.target);
  const identities = new Set<string>([`target:${normalizedTarget}`]);
  if (scan.target.includes("/")) return identities;
  identities.add(`${isLiteralAddress(scan.target) ? "address" : "name"}:${normalizedTarget}`);
  page?.items.forEach((host) => {
    if (host.address) identities.add(`address:${host.address.trim().toLowerCase()}`);
    if (host.hostname) identities.add(`name:${normalizeScanTarget(host.hostname)}`);
  });
  return identities;
}

function isLiteralAddress(value: string): boolean {
  const normalized = value.trim().replace(/^\[|\]$/g, "");
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(normalized) || normalized.includes(":");
}

function singleAddressTarget(value: string): string | undefined {
  const normalized = value.trim().replace(/^\[|\]$/g, "");
  const prefix = normalized.match(/\/(\d+)$/)?.[1];
  if (prefix !== undefined && prefix !== "32" && prefix !== "128") return undefined;
  const address = normalized.replace(/\/(?:32|128)$/, "");
  return isLiteralAddress(address) ? address : undefined;
}

function formatElapsed(scan: Scan, now: number): string {
  const start = new Date(scan.startedAt ?? scan.createdAt).getTime();
  const end = scan.finishedAt ? new Date(scan.finishedAt).getTime() : now;
  const seconds = Math.max(0, Math.floor((end - start) / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function boundedPercent(value?: string): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.max(2, Math.min(100, parsed)) : 2;
}

function scopeSize(target: string): number | undefined {
  const match = target.match(/\/(\d{1,2})$/);
  if (!match) return undefined;
  const prefix = Number(match[1]);
  return prefix >= 23 && prefix <= 32 ? 2 ** (32 - prefix) : undefined;
}

function viewForPrefix(length: IPv4Prefix["length"]): SceneView {
  if (length === 24) return "range24";
  if (length === 16) return "range16";
  if (length === 8) return "range8";
  return "all";
}
