import { Line, OrbitControls } from "@react-three/drei";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Color, InstancedMesh, Mesh, Object3D, QuadraticBezierCurve3, Vector3 } from "three";
import type { OrbitControls as OrbitControlsImpl } from "three-stdlib";
import type { SceneGroup, SceneLink, SceneNode, SceneStyle, SceneWaypoint } from "./layout";
import { sceneExtent } from "./layout";

interface NetworkSceneProps {
  active: boolean;
  focus: [number, number, number];
  groups: SceneGroup[];
  links: SceneLink[];
  waypoints: SceneWaypoint[];
  nodes: SceneNode[];
  style: SceneStyle;
  selectedKey?: string;
  onEnterGroup: (group: SceneGroup) => void;
  onSelect: (node: SceneNode) => void;
}

const colors: Record<SceneNode["state"], Color> = {
  pending: new Color("#243934"),
  provisional: new Color("#f0b85c"),
  up: new Color("#73f6bc"),
  "no-response": new Color("#26302e"),
  down: new Color("#493b42"),
};

const noOpenPorts = new Color("#ed625c");
const webService = new Color("#55a9ff");
const hostVisualScale = 1.5;
const minimumHostHitRadius = 0.72;

function colorForNode(node: SceneNode): Color {
  if (node.state !== "up") return colors[node.state];
  if (node.webAvailable) return webService;
  if (node.openPortCount === 0) return noOpenPorts;
  return colors.up;
}

export function NetworkScene({ active, focus, groups, links, nodes, waypoints, style, selectedKey, onEnterGroup, onSelect }: NetworkSceneProps) {
  const [hovered, setHovered] = useState<SceneNode>();
  const [hoveredGroup, setHoveredGroup] = useState<SceneGroup>();
  const [hoveredWaypoint, setHoveredWaypoint] = useState<SceneWaypoint>();
  const selected = nodes.find((node) => node.key === selectedKey);
  const prefixField = style === "original" && groups.some((group) => group.prefixLength !== undefined);

  useEffect(() => {
    setHoveredGroup(undefined);
  }, [groups]);

  return (
    <div className="scene-wrap" onPointerLeave={() => { setHovered(undefined); setHoveredGroup(undefined); setHoveredWaypoint(undefined); }}>
      <Canvas
        camera={{ fov: 44, near: 0.1, far: 1000, position: [0, 16, 18] }}
        dpr={[1, 1.75]}
        fallback={<div className="webgl-required">Lantern requires WebGL to render the network field.</div>}
        gl={{ antialias: true, powerPreference: "high-performance" }}
        onPointerMissed={() => setHovered(undefined)}
      >
        <color attach="background" args={["#07100f"]} />
        <fog attach="fog" args={["#07100f", 90, 520]} />
        <ambientLight intensity={0.9} />
        <directionalLight position={[8, 14, 7]} intensity={2.2} color="#d7fff0" />
        <pointLight position={[-8, 5, -6]} intensity={30} distance={24} color="#56d6aa" />
        <SceneCamera focus={focus} groups={groups} nodes={nodes} selected={selected} style={style} />
        <ObservationField groups={groups} style={style} onEnter={onEnterGroup} onHover={setHoveredGroup} />
        {style === "map" && <TopologyLayer links={links} waypoints={waypoints} onHover={setHoveredWaypoint} />}
        <HostInstances nodes={nodes} onHover={(node) => { setHovered(node); if (node) { setHoveredGroup(undefined); setHoveredWaypoint(undefined); } }} onSelect={onSelect} />
        {selected && <SelectionMarker node={selected} />}
      </Canvas>

      <div className="scene-legend" aria-hidden="true">
        {prefixField && <span><i className="legend-range-observed" />Scanned range</span>}
        {(nodes.length > 0 || !prefixField) && <span><i className="legend-web" />Web (80/443)</span>}
        {(nodes.length > 0 || !prefixField) && <span><i className="legend-none" />No open ports</span>}
        {(nodes.length > 0 || !prefixField) && <span><i className="legend-up" />Other services</span>}
        {(nodes.length > 0 || !prefixField) && <span><i className="legend-provisional" />Discovered</span>}
        {(nodes.length > 0 || !prefixField) && <span><i className="legend-pending" />{active ? "Pending" : "No response"}</span>}
        {style === "map" && <span><i className="legend-route" />Route hop</span>}
      </div>

      {hovered && (
        <div className="scene-hover">
          <span>{labelForState(hovered.state)}</span>
          <strong>{hovered.label}</strong>
          <em>{hovered.scanLabel}</em>
          <small>{hovered.openPortCount} open service{hovered.openPortCount === 1 ? "" : "s"}</small>
        </div>
      )}

      {!hovered && hoveredGroup && (
        <div className="scene-hover scope-hover">
          <span>Address range</span>
          <strong>{hoveredGroup.label}</strong>
          {hoveredGroup.dnsRoot && <em>DNS · {hoveredGroup.dnsRoot}</em>}
          <small>/{hoveredGroup.prefixLength ?? "?"} prefix sphere</small>
        </div>
      )}

      {!hovered && !hoveredGroup && hoveredWaypoint && (
        <div className="scene-hover scope-hover">
          <span>Route hop</span>
          <strong>{hoveredWaypoint.label}</strong>
        </div>
      )}
    </div>
  );
}

function SceneCamera({ focus, groups, nodes, selected, style }: { focus: [number, number, number]; groups: SceneGroup[]; nodes: SceneNode[]; selected?: SceneNode; style: SceneStyle }) {
  const controls = useRef<OrbitControlsImpl>(null);
  const camera = useThree((state) => state.camera);
  const extent = useMemo(() => sceneExtent(nodes, groups, focus), [focus, groups, nodes]);

  useEffect(() => {
    if (style === "map") camera.position.set(focus[0], Math.max(14, extent * 0.9), focus[2] + 0.01);
    else camera.position.set(focus[0], focus[1] + Math.max(12, extent * 0.78), focus[2] + Math.max(14, extent * 0.9));
    controls.current?.target.set(...focus);
    controls.current?.update();
  }, [camera, extent, focus, style]);

  useEffect(() => {
    if (!selected || !controls.current) return;
    controls.current.target.set(...selected.position);
    controls.current.update();
  }, [selected]);

  return (
    <OrbitControls
      ref={controls}
      makeDefault
      enableDamping
      zoomToCursor
      dampingFactor={0.075}
      minDistance={4}
      maxDistance={500}
      maxPolarAngle={Math.PI}
    />
  );
}

function TopologyLayer({ links, waypoints, onHover }: { links: SceneLink[]; waypoints: SceneWaypoint[]; onHover: (waypoint?: SceneWaypoint) => void }) {
  return (
    <group>
      {links.map((link) => <TopologyLink link={link} key={link.key} />)}
      {waypoints.map((waypoint) => (
        <mesh
          key={waypoint.key}
          position={waypoint.position}
          onPointerMove={(event) => { event.stopPropagation(); onHover(waypoint); }}
          onPointerOut={() => onHover(undefined)}
        >
          <octahedronGeometry args={[waypoint.key === "local" ? 0.24 : 0.14, 0]} />
          <meshStandardMaterial color={waypoint.key === "local" ? "#e8b65d" : "#4b8f78"} roughness={0.5} />
        </mesh>
      ))}
    </group>
  );
}

function TopologyLink({ link }: { link: SceneLink }) {
  const points = useMemo(() => {
    const start = new Vector3(...link.start);
    const end = new Vector3(...link.end);
    const deltaX = end.x - start.x;
    const deltaZ = end.z - start.z;
    const length = Math.max(0.001, Math.hypot(deltaX, deltaZ));
    const direction = stableParity(link.key) ? 1 : -1;
    const bend = Math.min(0.7, length * 0.14) * direction;
    const control = new Vector3(
      (start.x + end.x) / 2 - (deltaZ / length) * bend,
      0.06,
      (start.z + end.z) / 2 + (deltaX / length) * bend,
    );
    return new QuadraticBezierCurve3(start, control, end).getPoints(16);
  }, [link]);
  return <Line points={points} color="#285c4d" transparent opacity={0.72} lineWidth={1} />;
}

function stableParity(value: string): boolean {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) hash = (hash * 31 + value.charCodeAt(index)) | 0;
  return (hash & 1) === 0;
}

function ObservationField({ groups, style, onHover, onEnter }: {
  groups: SceneGroup[];
  style: SceneStyle;
  onHover: (group?: SceneGroup) => void;
  onEnter: (group: SceneGroup) => void;
}) {
  return (
    <group>
      {groups.map((group) => <ScopeGuide group={group} style={style} key={group.key} onEnter={onEnter} onHover={onHover} />)}
    </group>
  );
}

function ScopeGuide({ group, style, onHover, onEnter }: {
  group: SceneGroup;
  style: SceneStyle;
  onHover: (group?: SceneGroup) => void;
  onEnter: (group: SceneGroup) => void;
}) {
  const nestedPrefix = group.prefixLength !== undefined;
  const prefixOpacity = group.prefixLength === 0 ? 0.16 : group.prefixLength === 8 ? 0.3 : group.prefixLength === 16 ? 0.26 : 0.22;
  const prefixColor = group.prefixLength === 8 ? "#3d9f7e" : group.prefixLength === 16 ? "#328b70" : "#2c765f";
  return (
    <group position={group.center}>
      {nestedPrefix && (
        <mesh
          userData={{ sceneGroup: group }}
          onPointerMove={(event) => onHover(deepestPrefix(event))}
          onPointerOut={() => onHover(undefined)}
          onDoubleClick={(event) => {
            const target = deepestPrefix(event);
            if (target) onEnter(target);
          }}
          onWheel={(event) => {
            if (event.deltaY >= 0) return;
            const target = deepestPrefix(event);
            if (target) onEnter(target);
          }}
        >
          <icosahedronGeometry args={[group.radius, group.prefixLength === 24 ? 3 : 2]} />
          <meshBasicMaterial color={prefixColor} wireframe transparent opacity={prefixOpacity} depthWrite={false} toneMapped={false} />
        </mesh>
      )}
      {nestedPrefix && (
        <mesh scale={0.995}>
          <icosahedronGeometry args={[group.radius, group.prefixLength === 24 ? 3 : 2]} />
          <meshBasicMaterial color={prefixColor} transparent opacity={0.018} depthWrite={false} />
        </mesh>
      )}
      {!nestedPrefix && style === "original" && (
        <mesh>
          <icosahedronGeometry args={[group.radius, 3]} />
          <meshBasicMaterial color="#1d5647" wireframe transparent opacity={0.1} />
        </mesh>
      )}
      {group.active && <ActiveEnvelope radius={group.radius * 1.08} />}
    </group>
  );
}

function deepestPrefix(event: { intersections: Array<{ object: Object3D }> }): SceneGroup | undefined {
  return event.intersections
    .map((intersection) => intersection.object.userData.sceneGroup as SceneGroup | undefined)
    .filter((group): group is SceneGroup => group !== undefined)
    .sort((left, right) => (right.prefixLength ?? -1) - (left.prefixLength ?? -1))[0];
}

function ActiveEnvelope({ radius }: { radius: number }) {
  const mesh = useRef<Mesh>(null);
  useFrame(({ clock }) => {
    if (!mesh.current) return;
    const scale = 1 + Math.sin(clock.elapsedTime * 1.8) * 0.035;
    mesh.current.scale.setScalar(scale);
    mesh.current.rotation.y = clock.elapsedTime * 0.08;
  });
  return (
    <mesh ref={mesh}>
      <icosahedronGeometry args={[radius, 2]} />
      <meshBasicMaterial color="#e8b65d" wireframe transparent opacity={0.18} />
    </mesh>
  );
}

function HostInstances({ nodes, onHover, onSelect }: {
  nodes: SceneNode[];
  onHover: (node?: SceneNode) => void;
  onSelect: (node: SceneNode) => void;
}) {
  const visualMesh = useRef<InstancedMesh>(null);
  const hitMesh = useRef<InstancedMesh>(null);

  useLayoutEffect(() => {
    if (!visualMesh.current || !hitMesh.current) return;
    const transform = new Object3D();
    nodes.forEach((node, index) => {
      transform.position.set(...node.position);
      transform.scale.setScalar(node.scale * hostVisualScale);
      transform.updateMatrix();
      visualMesh.current!.setMatrixAt(index, transform.matrix);
      visualMesh.current!.setColorAt(index, colorForNode(node));

      transform.scale.setScalar(Math.max(node.scale * hostVisualScale, minimumHostHitRadius));
      transform.updateMatrix();
      hitMesh.current!.setMatrixAt(index, transform.matrix);
    });
    visualMesh.current.count = nodes.length;
    visualMesh.current.instanceMatrix.needsUpdate = true;
    if (visualMesh.current.instanceColor) visualMesh.current.instanceColor.needsUpdate = true;
    visualMesh.current.computeBoundingSphere();
    hitMesh.current.count = nodes.length;
    hitMesh.current.instanceMatrix.needsUpdate = true;
    hitMesh.current.computeBoundingSphere();
  }, [nodes]);

  function nodeFrom(instanceID: number | undefined): SceneNode | undefined {
    return instanceID === undefined ? undefined : nodes[instanceID];
  }

  if (nodes.length === 0) return null;
  return (
    <group>
      <instancedMesh ref={visualMesh} args={[undefined, undefined, nodes.length]}>
        <icosahedronGeometry args={[1, 1]} />
        <meshStandardMaterial roughness={0.34} metalness={0.18} emissive="#102d26" emissiveIntensity={0.45} />
      </instancedMesh>
      <instancedMesh
        ref={hitMesh}
        args={[undefined, undefined, nodes.length]}
        onClick={(event) => {
          event.stopPropagation();
          const node = nodeFrom(event.instanceId);
          if (node) onSelect(node);
        }}
        onPointerMove={(event) => {
          event.stopPropagation();
          onHover(nodeFrom(event.instanceId));
        }}
        onPointerOut={() => onHover(undefined)}
      >
        <icosahedronGeometry args={[1, 1]} />
        <meshBasicMaterial transparent opacity={0} depthWrite={false} colorWrite={false} />
      </instancedMesh>
    </group>
  );
}

function SelectionMarker({ node }: { node: SceneNode }) {
  const marker = useRef<Mesh>(null);
  useFrame(({ clock }) => {
    if (!marker.current) return;
    const scale = 1 + Math.sin(clock.elapsedTime * 3) * 0.08;
    marker.current.scale.setScalar(scale);
    marker.current.rotation.z = clock.elapsedTime * 0.3;
  });
  return (
    <mesh ref={marker} position={node.position}>
      <icosahedronGeometry args={[0.56, 2]} />
      <meshBasicMaterial color="#fff0b5" wireframe transparent opacity={0.9} />
    </mesh>
  );
}

function labelForState(state: SceneNode["state"]): string {
  if (state === "no-response") return "No response";
  if (state === "provisional") return "Discovered";
  return state[0].toUpperCase() + state.slice(1);
}
