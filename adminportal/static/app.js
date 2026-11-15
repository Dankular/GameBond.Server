"use strict";
const NAV = [
  ["Home", "home", [["overview", "Overview"], ["uplinks", "Uplinks"]]],
  ["Devices", "devices", [["devices", "Connected Devices"]]],
  ["Network", "network", [["interfaces", "Interfaces"], ["routes", "Routing"], ["server-network", "Server network"], ["queues", "QoS & Queues"]]],
  ["Security", "security", [["firewall", "Firewall (NAT)"]]],
  ["Insights", "insights", [["bandwidth", "Realtime Graphs"], ["log", "System Log"]]],
  ["Labs", "labs", [["labs", "Topology Designer"]]],
  ["Settings", "settings", [["config", "Configuration"], ["admin", "Administration"], ["restart", "Restart Service"]]],
];
let csrf = null, timer = null, routeVersion = 0, currentIdentity = null;
const $ = (id) => document.getElementById(id);
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) k === "class" ? (e.className = v) : k.startsWith("on") ? e.addEventListener(k.slice(2), v) : e.setAttribute(k, v);
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
async function api(path, body) {
  const opt = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf || "" }, body: JSON.stringify(body) };
  const r = await fetch("/api/" + path, opt);
  if (r.status === 401 && path !== "login") { csrf = null; await boot(); throw new Error("login required"); }
  return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
}
const fmtBytes = (n) => n == null ? "—" : n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KiB" : n < 1073741824 ? (n / 1048576).toFixed(1) + " MiB" : (n / 1073741824).toFixed(2) + " GiB";
const kv = (rows) => h("table", { class: "kv" }, rows.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", {}, v))));
const grid = (head, rows, cls) => h("table", {}, h("tr", {}, head.map((c) => h("th", {}, c))), rows.map((r) => h("tr", { class: cls ? cls(r) : "" }, r.map((c) => h("td", {}, c)))));
const pct = (v, label) => h("div", { class: "bar" }, h("i", { style: "" }), h("span", {}, label));
function bar(frac, label) { const b = pct(); b.firstChild.style.width = Math.max(0, Math.min(1, frac)) * 100 + "%"; b.lastChild.textContent = label; return b; }
const err = (e) => h("p", { class: "bad" }, "Unavailable: " + (e.error || e));
const serverNetworkFeatureOrder = [
  ["stp", "STP"], ["rstp", "RSTP"], ["loop_protection", "Loop protection"], ["redundancy", "Redundancy coordination"],
  ["lacp_port_aggregation", "LACP aggregation"], ["mc_lag", "MC-LAG"], ["bridge_vlan", "VLAN filtering"], ["virtual_network_override", "Virtual network overrides"],
  ["jumbo_frames", "Jumbo frames"], ["port_isolation", "Port isolation"], ["mac_port_restriction", "MAC port restriction"], ["mac_address_blocking", "MAC address blocking"],
  ["mac_acl_device_isolation", "MAC ACL / device isolation"], ["ip_acl_network_isolation", "IP ACL / network isolation"], ["routed_network_isolation", "Routed network isolation"],
  ["igmp_snooping", "IGMP snooping"], ["igmp_vlan_snooping", "Per-VLAN IGMP snooping"], ["igmp_advanced", "IGMP querier / fast leave / router port"],
  ["dhcp_snooping_guarding", "DHCP snooping / source guard"], ["dhcp_lease_binding_guard", "DHCP lease binding guard"], ["8021x_control", "802.1X control"],
  ["voice_vlan", "Voice VLAN"], ["lldp_med", "LLDP-MED"], ["egress_rate_limit", "Egress rate limit"], ["flow_control", "Ethernet flow control"],
  ["qos_dscp", "QoS (DSCP)"], ["storm_control", "Storm control"], ["multicast_broadcast_rate_limit", "Multicast / broadcast rate limits"],
  ["port_mirroring", "Port mirroring"], ["vxlan_bridge_tap", "VXLAN bridge / EVPN data plane"], ["vrrp_gateway_failover", "VRRP gateway failover"],
];
const prettyJSON = (value) => h("pre", { class: "network-json" }, JSON.stringify(value ?? {}, null, 2));

function renderNav(current) {
  const nav = $("nav"); nav.replaceChildren();
  if (!csrf) return;
  const visible = currentIdentity && currentIdentity.role !== "system-admin" ? NAV.filter(([,slug])=>slug==="labs") : NAV.map(section=>section[1]==="settings"&&!currentIdentity?.legacy_admin?[section[0],section[1],section[2].filter(([id])=>id!=="admin")]:section);
  for (const [title, slug, items] of visible) nav.append(h("div", { class: "item" }, h("button", { class: "top", type: "button" }, title + " ▾"),
    h("div", { class: "menu" }, items.map(([id, label]) => h("a", { href: "#/" + slug + "/" + id, class: current === id ? "on" : "" }, label)))));
  nav.append(h("a", { class: "top", href: "#/logout" }, "Logout"));
}

async function login() {
  const view = $("view"); view.replaceChildren();
  const username = h("input", { type: "text", autocomplete: "username", value:"admin" }), pw = h("input", { type: "password", autocomplete: "current-password" }), msg = h("p", { class: "bad" });
  const go = async () => { const r = await api("login", { username:username.value, password: pw.value }); if (r.ok) { csrf = r.data.csrf; currentIdentity=r.data.identity; location.hash = currentIdentity.role==="admin" ? "#/home/overview" : "#/labs/labs"; route(); } else msg.textContent = r.data.error || "Login failed"; };
  pw.addEventListener("keydown", (e) => e.key === "Enter" && go());
  view.append(h("h2", {}, "Authorization Required"), h("p", {}, "Enter your GameBond portal credentials."), h("div", { class: "row" }, h("label", {}, "Username"), username), h("div", { class: "row" }, h("label", {}, "Password"), pw), h("div", { class: "row" }, h("button", { class: "primary", onclick: go }, "Login")), msg);
  username.focus();
}

const pages = {
  async overview(active = () => true) {
    const s = (await api("status")).data, gateway = (await api("gateway/status")).data, clock = gateway.clock || {}, t = s.transport, paths = t.paths || [], up = paths.filter((p) => p.healthy).length;
    const l2 = s.config.layer2 || { enabled: false }, capabilities = Object.entries(s.layer2_capabilities || {});
    if (active()) $("notice").replaceChildren(...(up < paths.length ? [h("div", { class: "notice" }, h("b", {}, up ? "Degraded" : "No client connected"), `${up} of ${paths.length} uplinks healthy.`)] : []));
    return [h("h2", {}, "Status"), h("h3", {}, "System"), kv([["Version", s.version], ["Process ID", s.pid], ["Observed", s.observed_at], ["Bonding mode", s.config.bonding_mode ? "enabled" : "disabled"], ["Tunnel MTU", s.config.mtu]]),
      h("h3", {}, "Host clock"), kv([["NTP enabled", clock.ntp_enabled == null ? "unknown" : clock.ntp_enabled ? "yes" : "no"], ["Synchronized", clock.synchronized == null ? "unknown" : clock.synchronized ? "yes" : "no"], ["Timezone", clock.timezone || "—"], ["Status", clock.error || gateway.error || (gateway.available === false ? "Gateway status unavailable" : "—")]]),
      h("h3", {}, "Tunnel"), kv([["Uplinks healthy", `${up} / ${paths.length}`], ["Client tunnel address", s.config.client_tunnel_ip], ["Listening", s.config.bind.map((b) => b.join(":")).join(", ")],
        ["Dropped (wrong address)", s.packets.wrong_tunnel_address], ["Dropped (no path)", s.packets.no_path_drops], ["Malformed", s.packets.malformed]]),
      h("h3", {}, "Layer 2"), kv([["Enabled", l2.enabled ? "yes" : "no"], ["Segment", l2.segment_id || "—"], ["Gateway VLANs", (l2.gateway_vlans || []).join(", ") || "—"],
        ["Tunnel VLAN policy", JSON.stringify(l2.tunnel_vlan || {})], ["Exit VLAN policy", JSON.stringify(l2.exit_vlan || {})],
        ["Monitor TAP", l2.monitor?.tap_name || "disabled"], ["Monitor directions", l2.monitor ? Object.entries(l2.monitor).filter(([key, value]) => key !== "tap_name" && value).map(([key]) => key).join(", ") : "—"]]),
      h("h4", {}, "Layer 2 capabilities"), grid(["Capability", "State", "Reason"], capabilities.map(([name, value]) => [name, value.state, value.reason])),
      h("h4", {}, "Layer 2 runtime"), h("pre", {}, JSON.stringify(s.layer2 || {}, null, 2))];
  },
  async uplinks() {
    const t = (await api("status")).data.transport;
    return [h("h2", {}, "Uplinks"), grid(["Slot", "Remote", "State", "RTT", "Jitter", "TX", "RX", "Errors"], (t.paths || []).map((p) => [p.slot, p.remote ? p.remote.join(":") : "—", p.healthy ? "healthy" : p.available ? "unhealthy" : "unavailable", p.rtt_ms == null ? "—" : p.rtt_ms.toFixed(1) + " ms", p.rtt_jitter_ms == null ? "—" : p.rtt_jitter_ms.toFixed(1) + " ms", fmtBytes(p.wire_tx_bytes), fmtBytes(p.wire_rx_bytes), JSON.stringify(p.errors || {})]), (r) => r[2] === "healthy" ? "" : "bad")];
  },
  async queues() {
    const s = (await api("status")).data, q = s.queues, stats = q.per_dscp_stats || {};
    return [h("h2", {}, "QoS & Queues"), h("h3", {}, "Scheduler"), kv([["Queued packets", `${q.queued_packets ?? q.queued} / ${q.capacity_packets ?? "—"}`], ["Mean residence", (q.residence_ms?.mean ?? 0).toFixed(2) + " ms"]]),
      h("h3", {}, "Per DSCP"), grid(["DSCP", "Enqueued", "Dequeued", "Stale drops", "Full drops", "Queued"], Object.entries(stats).map(([d, v]) => [d, v.enqueued, v.dequeued, v.dropped_stale, v.dropped_full, v.queued])),
      h("h3", {}, "Configured queues"), h("pre", {}, JSON.stringify(s.config.queues, null, 2)), h("p", { class: "muted" }, "Game UDP ports: " + (s.config.game_udp_ports.join(", ") || "none"))];
  },
  async bandwidth(active = () => true) {
    const cv = h("canvas", { width: 900, height: 200 }), info = h("p", { class: "muted" }, "Sampling…");
    drawBw(cv, info, active);
    return [h("h2", {}, "Realtime Graphs"), h("h3", {}, "Bandwidth (all uplinks, wire bytes)"), cv, info];
  },
  async firewall() { const r = (await api("nat")).data; return [h("h2", {}, "Firewall (NAT)"), r.error ? err(r) : h("pre", {}, r.text)]; },
  async log() { const r = (await api("log")).data; return [h("h2", {}, "System Log"), h("p", { class: "muted" }, "Portal events and uplink health samples since the last service start."), h("pre", {}, r.lines.join("\n") || "(empty)")]; },
  async labs(active = () => true) {
    const status = (await api("labs/status")).data;
    const saved = (await api("labs/topologies")).data.topologies || [];
    const name = h("input", { placeholder: "Topology name", value: "New lab" });
    const id = h("input", { placeholder: "stable-id", value: "new-lab" });
    const json = h("textarea", { spellcheck: "false", rows: "22" });
    const msg = h("p", {}), output = h("pre", {});
    json.value = JSON.stringify({version:1,id:"new-lab",name:"New lab",nodes:[{id:"host-a",name:"Host A",role:"host",interfaces:[{id:"eth0",name:"eth0",addresses:["198.18.0.2/30"]}]},{id:"router-a",name:"Router A",role:"router",interfaces:[{id:"eth0",name:"eth0",addresses:["198.18.0.1/30"]}]}],links:[{id:"link-a",a:{node:"host-a",interface:"eth0"},b:{node:"router-a",interface:"eth0"},impairment:{}}],assertions:[]}, null, 2);
    let topology = JSON.parse(json.value), selected = null, linkStart = null, drawingLink = false;
    const canvas = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    canvas.setAttribute("viewBox", "0 0 900 460"); canvas.setAttribute("role", "img"); canvas.setAttribute("aria-label", "Draggable lab topology canvas");
    canvas.style.cssText = "width:100%;min-height:320px;border:1px solid #d9dfe7;border-radius:8px;background-color:#fbfcfe;background-image:radial-gradient(#dce2ea 1px,transparent 1px);background-size:18px 18px;touch-action:none";
    const props = h("div", {class:"row"});
    const consolePanel = h("section", {class:"card"}); let consoleSocket = null;
    const closeConsole = () => { if (consoleSocket) { consoleSocket.close(); consoleSocket = null; } };
    window.addEventListener("hashchange", closeConsole, {once:true});
    const sync = () => { drawCanvas(); json.value = JSON.stringify(topology, null, 2); };
    const drawCanvas = () => {
      canvas.replaceChildren();
      const add = (tag, attrs) => { const e=document.createElementNS(canvas.namespaceURI,tag); for(const [k,v] of Object.entries(attrs)) e.setAttribute(k,String(v)); canvas.append(e); return e; };
      for (const link of topology.links) {
        const a=topology.nodes.find(n=>n.id===link.a.node), b=topology.nodes.find(n=>n.id===link.b.node); if(!a||!b) continue;
        const pa=a.position||{x:150,y:120}, pb=b.position||{x:550,y:260}; const line=add("line",{x1:pa.x+70,y1:pa.y+25,x2:pb.x+70,y2:pb.y+25,stroke:selected===link.id?"#0f7ae5":"#687486","stroke-width":selected===link.id?5:3,cursor:"pointer"});
        line.addEventListener("click",()=>{selected=link.id;drawCanvas();});
      }
      for (const [i,node] of topology.nodes.entries()) {
        node.position ||= {x:150+(i%3)*250,y:100+Math.floor(i/3)*160};
        const p=node.position, g=add("g",{transform:`translate(${p.x} ${p.y})`,class:"lab-node",cursor:drawingLink?"crosshair":"grab"});
        const rect=document.createElementNS(canvas.namespaceURI,"rect"); rect.setAttribute("width","145");rect.setAttribute("height","54");rect.setAttribute("rx","8");rect.setAttribute("fill","white");rect.setAttribute("stroke",selected===node.id?"#0f7ae5":"#9aa4b2");rect.setAttribute("stroke-width",selected===node.id?"3":"1.5");g.append(rect);
        const label=document.createElementNS(canvas.namespaceURI,"text");label.setAttribute("x","10");label.setAttribute("y","22");label.textContent=node.name;g.append(label);
        const sub=document.createElementNS(canvas.namespaceURI,"text");sub.setAttribute("x","10");sub.setAttribute("y","42");sub.setAttribute("font-size","11");sub.setAttribute("fill","#687486");sub.textContent=node.role;g.append(sub);canvas.append(g);
        g.addEventListener("click",e=>{e.stopPropagation();if(drawingLink){if(!linkStart){linkStart=node.id;msg.textContent="Select the second node to connect.";}else if(linkStart!==node.id){const a=topology.nodes.find(n=>n.id===linkStart),b=node;const endpoint=(n)=>{let x=n.interfaces.find(i=>!topology.links.some(l=>(l.a.node===n.id&&l.a.interface===i.id)||(l.b.node===n.id&&l.b.interface===i.id)));if(!x){x={id:`eth${n.interfaces.length}`,name:`eth${n.interfaces.length}`};n.interfaces.push(x);}return {node:n.id,interface:x.id};};topology.links.push({id:`link-${topology.links.length+1}`,a:endpoint(a),b:endpoint(b),impairment:{}});drawingLink=false;linkStart=null;sync();}return;}selected=node.id;drawCanvas();});
        let dragging=false, offset={x:0,y:0};g.addEventListener("pointerdown",e=>{if(drawingLink)return;dragging=true;const r=canvas.getBoundingClientRect();offset={x:e.clientX-r.left-p.x*r.width/900,y:e.clientY-r.top-p.y*r.height/460};g.setPointerCapture(e.pointerId);});g.addEventListener("pointermove",e=>{if(!dragging)return;const r=canvas.getBoundingClientRect();p.x=Math.max(0,Math.min(740,Math.round((e.clientX-r.left-offset.x)*900/r.width)));p.y=Math.max(0,Math.min(400,Math.round((e.clientY-r.top-offset.y)*460/r.height)));g.setAttribute("transform",`translate(${p.x} ${p.y})`);});g.addEventListener("pointerup",()=>{if(dragging){dragging=false;sync();}});
      }
      props.replaceChildren();
      const node=topology.nodes.find(n=>n.id===selected), link=topology.links.find(l=>l.id===selected);
      if(node){const nodeName=h("input",{value:node.name,"aria-label":"Node name"}),role=h("select",{"aria-label":"Node role"},["host","router","switch"].map(v=>h("option",{value:v},v))),addresses=h("input",{value:(node.interfaces[0]?.addresses||[]).join(", "),placeholder:"Interface addresses, e.g. 192.0.2.1/24","aria-label":"Addresses"});role.value=node.role;nodeName.addEventListener("change",()=>{node.name=nodeName.value;sync();});role.addEventListener("change",()=>{node.role=role.value;sync();});addresses.addEventListener("change",()=>{node.interfaces[0].addresses=addresses.value.split(",").map(v=>v.trim()).filter(Boolean);sync();});const openConsole=h("button",{onclick:()=>{closeConsole();consolePanel.replaceChildren();const out=h("pre",{style:"height:220px;overflow:auto;background:#111;color:#eee;padding:10px"},"Connecting to "+node.name+"…"),input=h("input",{placeholder:"Type in the node shell",autocomplete:"off",autocapitalize:"off",spellcheck:"false"}),close=h("button",{onclick:closeConsole},"Close console");const scheme=location.protocol==="https:"?"wss:":"ws:";const ws=new WebSocket(`${scheme}//${location.host}/api/labs/console?node=${encodeURIComponent(node.id)}`);consoleSocket=ws;ws.binaryType="arraybuffer";ws.onopen=()=>{out.textContent="Connected to "+node.name+". Keystrokes go directly to the node shell.\n";input.focus();};ws.onmessage=e=>{out.textContent+=typeof e.data==="string"?e.data:new TextDecoder().decode(e.data);out.scrollTop=out.scrollHeight;};ws.onerror=()=>{out.textContent+="\nConsole connection failed.";};ws.onclose=()=>{if(consoleSocket===ws)consoleSocket=null;};input.addEventListener("keydown",e=>{if(ws.readyState!==WebSocket.OPEN)return;let key=null;if(e.key==="Enter")key="\r";else if(e.key==="Backspace")key="\x7f";else if(e.key==="Tab")key="\t";else if(e.key==="ArrowUp")key="\x1b[A";else if(e.key==="ArrowDown")key="\x1b[B";else if(e.key==="ArrowRight")key="\x1b[C";else if(e.key==="ArrowLeft")key="\x1b[D";else if(e.ctrlKey&&e.key.toLowerCase()==="c")key="\x03";else if(e.ctrlKey&&e.key.toLowerCase()==="d")key="\x04";else if(e.ctrlKey&&e.key.toLowerCase()==="l")key="\x0c";else if(e.key.length===1&&!e.ctrlKey&&!e.metaKey)key=e.key;if(key!==null){e.preventDefault();ws.send(key);input.value="";}});input.addEventListener("paste",e=>{if(ws.readyState===WebSocket.OPEN){e.preventDefault();ws.send(e.clipboardData.getData("text"));}});consolePanel.append(h("h3",{},"Console: "+node.name),out,input,close);}},"Open node console"),faultLoss=h("input",{type:"number",min:"0",max:"100",step:"0.1",value:"0","aria-label":"Interface loss percent"}),faultCorrupt=h("input",{type:"number",min:"0",max:"100",step:"0.1",value:"0","aria-label":"Interface corruption percent"}),inject=h("button",{onclick:()=>act("labs/action",{action:"interface-errors",node:node.id,interface:node.interfaces[0].id,impairment:{loss_pct:Number(faultLoss.value)||0,corrupt_pct:Number(faultCorrupt.value)||0}})},"Inject interface errors");props.append(h("strong",{},`Node: ${node.id}`),nodeName,role,addresses,openConsole,h("label",{},"Interface loss %",faultLoss),h("label",{},"Corruption %",faultCorrupt),inject);}
      if(link){const delay=h("input",{type:"number",min:"0",max:"60000",value:link.impairment.latency_ms||0,"aria-label":"Latency ms"}),loss=h("input",{type:"number",min:"0",max:"100",step:"0.1",value:link.impairment.loss_pct||0,"aria-label":"Loss percent"}),remove=h("button",{onclick:()=>{topology.links=topology.links.filter(x=>x!==link);selected=null;sync();}},"Delete link");const update=()=>{link.impairment.latency_ms=Number(delay.value)||0;link.impairment.loss_pct=Number(loss.value)||0;sync();};delay.addEventListener("change",update);loss.addEventListener("change",update);props.append(h("strong",{},`Link: ${link.id}`),h("label",{},"Latency ms",delay),h("label",{},"Loss %",loss),remove);}
    };
    json.addEventListener("change",()=>{try{topology=JSON.parse(json.value);selected=null;drawCanvas();}catch(e){msg.className="bad";msg.textContent="Invalid topology JSON: "+e.message;}});
    const act = async (path, body = {}) => { const r = await api(path, body); msg.className = r.ok ? "ok" : "bad"; msg.textContent = r.data.error || (r.ok ? "Saved." : "Request failed"); if (r.ok) output.textContent = JSON.stringify(r.data, null, 2); return r; };
    const buttons = h("div", {class:"row"},
      h("button", {onclick:()=>{const i=topology.nodes.length+1;topology.nodes.push({id:`host-${i}`,name:`Host ${i}`,role:"host",interfaces:[{id:"eth0",name:"eth0"}],position:{x:130+(i%3)*230,y:100+Math.floor(i/3)*145}});sync();}}, "Add host"),
      h("button", {onclick:()=>{const i=topology.nodes.length+1;topology.nodes.push({id:`router-${i}`,name:`Router ${i}`,role:"router",interfaces:[{id:"eth0",name:"eth0"}],position:{x:130+(i%3)*230,y:100+Math.floor(i/3)*145}});sync();}}, "Add router"),
      h("button", {onclick:()=>{drawingLink=true;linkStart=null;msg.textContent="Select two nodes to draw a point-to-point link.";}}, "Draw link"),
      h("button", {onclick: async () => { try { topology=JSON.parse(json.value); topology.id=id.value;topology.name=name.value;await act("labs/topologies", {topology}); } catch(e) {msg.className="bad";msg.textContent=e.message;} }}, "Save topology"),
      h("button", {onclick: async () => { try { topology=JSON.parse(json.value); topology.id=id.value;topology.name=name.value;await act("labs/apply", {topology}); } catch(e) {msg.className="bad";msg.textContent=e.message;} }}, "Apply topology"),
      h("button", {onclick: () => act("labs/action", {action:"rollback"})}, "Rollback"),
      h("button", {onclick: () => act("labs/action", {action:"pause"})}, "Pause"),
      h("button", {onclick: () => act("labs/action", {action:"resume"})}, "Resume"),
      h("button", {onclick: () => act("labs/check", {})}, "Run checks"));
    const select = h("select", {}, h("option", {value:""}, "Load saved topology"), saved.map(t => h("option", {value:t.id}, t.name)));
    select.addEventListener("change", () => { const t=saved.find(x=>x.id===select.value); if(t){topology=t;json.value=JSON.stringify(t,null,2);id.value=t.id;name.value=t.name;drawCanvas();} });
    if (active()) output.textContent = JSON.stringify(status, null, 2);
    sync();
    let membersPanel=null;
    if(currentIdentity?.role==="system-admin"||currentIdentity?.role==="team-admin"){
      membersPanel=h("section",{class:"card"},h("h3",{},"Team access"));
      const teamField=h("input",{value:currentIdentity.team,placeholder:"Team ID"}),userName=h("input",{placeholder:"Username"}),password=h("input",{type:"password",placeholder:"Temporary password (10+ characters)"}),userRole=h("select",{},h("option",{value:"editor"},"Editor"),h("option",{value:"viewer"},"Viewer"),...(currentIdentity.role==="system-admin"?[h("option",{value:"team-admin"},"Team admin")]:[])),memberList=h("div",{}),memberMsg=h("p",{});
      const scopedTeam=()=>currentIdentity.role==="system-admin"?teamField.value.trim():currentIdentity.team;
      const refreshUsers=async()=>{const data=(await api("labs/users?team="+encodeURIComponent(scopedTeam()))).data;memberList.replaceChildren(...(data.users||[]).map(u=>{const row=h("div",{class:"row"},h("span",{},`${u.username} · ${u.role}`));if(u.role!=="system-admin"&&u.role!=="team-admin")row.append(h("button",{onclick:async()=>{const r=await api("labs/users",{action:"delete",username:u.username,team:scopedTeam()});memberMsg.textContent=r.data.error||"User removed.";if(r.ok)refreshUsers();}},"Remove"));return row;}));};
      const addUser=h("button",{onclick:async()=>{const r=await api("labs/users",{action:"create",username:userName.value,password:password.value,role:userRole.value,team:scopedTeam()});memberMsg.className=r.ok?"ok":"bad";memberMsg.textContent=r.data.error||(r.ok?"Team user created.":"User was not created.");if(r.ok){userName.value="";password.value="";refreshUsers();}}},"Add team user");
      if(currentIdentity.role==="system-admin")teamField.addEventListener("change",refreshUsers);
      membersPanel.append(h("div",{class:"row"},...(currentIdentity.role==="system-admin"?[teamField]:[]),userName,password,userRole,addUser),memberList,memberMsg);refreshUsers();
    }
    const currentPassword=h("input",{type:"password",autocomplete:"current-password",placeholder:"Current password"}),freshPassword=h("input",{type:"password",autocomplete:"new-password",placeholder:"New password (10+ characters)"}),passwordMsg=h("p",{});
    const changePassword=h("section",{class:"card"},h("h3",{},"Account password"),h("div",{class:"row"},currentPassword,freshPassword,h("button",{onclick:async()=>{const r=await api("account/password",{current:currentPassword.value,new:freshPassword.value});passwordMsg.className=r.ok?"ok":"bad";passwordMsg.textContent=r.data.error||(r.ok?"Password changed. Sign in again.":"Password was not changed.");if(r.ok)setTimeout(()=>location.reload(),1000);}},"Change password")),passwordMsg);
    return [h("h2", {}, "Lab topology designer"), h("p", {class:"muted"}, status.available ? "Single host lab runtime is connected. Nodes use the configured sandbox runtime." : "Runtime is unavailable. Saved topologies can be edited; applying requires a configured lab backend."), membersPanel, changePassword, h("div",{class:"row"},name,id,select), buttons, canvas, props, consolePanel, h("h3",{},"Topology JSON"), json, msg, h("h3",{},"Live status / result"),output];
  },
  async interfaces() { const r = (await api("interfaces")).data; return [h("h2", {}, "Interfaces"), r.error ? err(r) : grid(["Name", "State", "MTU", "Addresses", "RX", "TX"], r.data.map((i) => [i.name, i.state, i.mtu, i.addresses.join(", "), fmtBytes(i.rx_bytes), fmtBytes(i.tx_bytes)]))]; },
  async "server-network"() {
    const [responseResult, serverResult] = await Promise.all([api("gateway/status"), api("status")]);
    const response = responseResult.data, server = serverResult.data;
    if (response.available === false) return [h("h2", {}, "Server network"), h("p", { class: "muted" }, "Read-only view of the Linux server gateway. " + (response.error || "Gateway status is unavailable."))];
    const config = (await api("gateway/config")).data, runtime = response.runtime || {}, layer2 = runtime.layer2 || {}, featureMap = layer2.features || {};
    const ordered = serverNetworkFeatureOrder.filter(([key]) => featureMap[key]).map(([key, label]) => [label, featureMap[key]]);
    const known = new Set(serverNetworkFeatureOrder.map(([key]) => key));
    Object.keys(featureMap).filter((key) => !known.has(key)).sort().forEach((key) => ordered.push([key.replaceAll("_", " "), featureMap[key]]));
    const state = (feature) => feature?.state || "unknown";
    const capabilityRows = ordered.map(([label, feature]) => [label, state(feature), feature.reason || "—"]);
    const configured = config.available === false ? null : config;
    const sections = [
      ["WAN, routing and availability", ["wans", "routing", "dynamic_routing", "vrrp", "redundancy", "interfaces"]],
      ["Layer 2 switching and port controls", ["layer2", "bridges"]],
      ["Forwarding, services and security", ["nat", "dhcp", "igmp_proxy", "mdns", "radius"]],
      ["Traffic management and visibility", ["qos", "telemetry", "features"]],
    ];
    const configDetails = configured ? sections.map(([title, keys]) => {
      const values = Object.fromEntries(keys.filter((key) => configured[key] !== undefined).map((key) => [key, configured[key]]));
      return h("details", {}, h("summary", {}, title + " · configured"), prettyJSON(values));
    }) : [h("p", { class: "muted" }, config.error || "Configured settings are unavailable.")];
    const runtimeDetails = [
      ["WAN quality and outages", runtime.quality], ["Routing and policy", runtime.routing], ["Dynamic routing and EVPN", runtime.dynamic_routing],
      ["VRRP and redundancy", { vrrp: runtime.vrrp, redundancy: runtime.redundancy }], ["Bridges and VLAN state", { bridges: runtime.bridges, layer2: layer2.bridge_vlans, overrides: layer2.virtual_network_overrides }],
      ["L2 guards and port controls", { dhcp_guard: layer2.dhcp_guard, port_auth: runtime.port_auth, mac_port_restrictions: layer2.mac_port_restrictions, mac_address_blocks: layer2.mac_address_blocks, mac_acls: layer2.mac_acls, ip_acls: layer2.ip_acls }],
      ["Multicast and discovery", { igmp_proxy: runtime.igmp_proxy, multicast_database: layer2.multicast_database, multicast_router_ports: layer2.multicast_router_ports, lldp_med: runtime.lldp_med }],
      ["Services and traffic", { nat: runtime.nat, dhcp: runtime.dhcp, qos: runtime.qos, egress_rate_limits: layer2.egress_rate_limits, storm_control: layer2.storm_control, multicast_broadcast_rate_limits: layer2.multicast_broadcast_rate_limits, port_mirrors: layer2.port_mirrors }],
    ];
    return [h("h2", {}, "Server network"), h("p", { class: "muted" }, "Read-only status for the Linux server gateway. Capability means the host/provider can support a feature; configured settings show desired state; runtime shows observed state."),
      h("h3", {}, "Host and provider capabilities"), layer2.error ? err(layer2.error) : grid(["Capability", "Host support", "Reason"], capabilityRows),
      h("h3", {}, "Configured settings"), h("details", {}, h("summary", {}, "Tunnel-side L2 · configured"), prettyJSON(server.config?.layer2 || {})), ...configDetails,
      h("h3", {}, "Observed runtime status"), ...runtimeDetails.map(([title, value]) => h("details", {}, h("summary", {}, title), prettyJSON(value)))];
  },
  async devices() {
    const s = (await api("status")).data, ips = s.config.lan_tunnel_ips;
    return [h("h2", {}, "Connected Devices"), h("p", { class: "muted" }, "Addresses the server accepts and NATs besides the client. Per-device counters are not collected by the server."),
      grid(["Tunnel address", "Role"], [[s.config.client_tunnel_ip, "Client (workstation)"], ...ips.map((ip) => [ip, "Connected device"])])];
  },
  async routes() { const r = (await api("routes")).data; return [h("h2", {}, "Routing"), r.error ? err(r) : grid(["Destination", "Gateway", "Device", "Protocol", "Source"], r.data.map((x) => [x.destination, x.gateway || "—", x.device, x.protocol || "—", x.source || "—"]))]; },
  async config() {
    const ta = h("textarea", { spellcheck: "false" }), out = h("p", {});
    ta.value = (await api("config")).data.text;
    const run = async (path) => { const r = await api(path, { text: ta.value }); out.className = r.data.ok ? "ok" : "bad"; out.textContent = r.data.ok ? (path === "config" ? "Saved. Restart the service to apply." : "Valid.") : r.data.error; };
    return [h("h2", {}, "Configuration"), h("p", { class: "muted" }, "The admin block is excluded from this editor. Changes take effect after a restart."), ta,
      h("div", { class: "row" }, h("button", { onclick: () => run("config/validate") }, "Validate"), h("button", { class: "primary", onclick: () => run("config") }, "Save")), out];
  },
  async admin() {
    const cur = h("input", { type: "password", autocomplete: "current-password" }), nw = h("input", { type: "password", autocomplete: "new-password" }), out = h("p", {});
    const go = async () => { const r = await api("password", { current: cur.value, new: nw.value }); out.className = r.data.ok ? "ok" : "bad"; out.textContent = r.data.ok ? "Password changed. Signing out…" : r.data.error; if (r.data.ok) setTimeout(() => location.reload(), 1200); };
    return [h("h2", {}, "Administration"), h("h3", {}, "Router Password"), h("div", { class: "row" }, h("label", {}, "Current"), cur), h("div", { class: "row" }, h("label", {}, "New (10+ characters)"), nw), h("button", { class: "primary", onclick: go }, "Save"), out];
  },
  async restart() {
    const out = h("p", {});
    const go = async () => { if (!confirm("Restart the GameBond service? The tunnel drops for a few seconds.")) return; const r = await api("restart", { confirm: true }); out.textContent = r.ok ? "Restart requested. Reconnecting…" : (r.data.error || "failed"); if (r.ok) waitBack(); };
    return [h("h2", {}, "Restart Service"), h("p", {}, "Restarts the tunnel process inside the container so saved configuration takes effect. Connected clients reconnect automatically once it is back."), h("button", { class: "danger", onclick: go }, "Restart now"), out];
  },
};

function waitBack() {
  const tick = async () => { try { const r = await fetch("/api/session"); if (r.ok) return location.reload(); } catch (_) {} setTimeout(tick, 2000); };
  setTimeout(tick, 3000);
}
function drawBw(cv, info, active = () => true) {
  const history = [];
  const ctx = cv.getContext("2d"); let last = null, sampling = false;
  const sample = async () => {
    if (!active() || !cv.isConnected || sampling) return;
    sampling = true;
    try {
      const response = await api("status");
      if (!active() || !cv.isConnected) return;
      const t = response.data.transport, tx = t.paths.reduce((a, p) => a + p.wire_tx_bytes, 0), rx = t.paths.reduce((a, p) => a + p.wire_rx_bytes, 0), now = performance.now();
      if (last) { const dt = (now - last.now) / 1000; history.push([(tx - last.tx) * 8 / dt / 1e6, (rx - last.rx) * 8 / dt / 1e6]); if (history.length > 120) history.shift(); }
      last = { tx, rx, now };
      const max = Math.max(1, ...history.flat()), css = getComputedStyle(document.body);
      ctx.clearRect(0, 0, cv.width, cv.height);
      [[0, "#d9534f"], [1, "#0069d6"]].forEach(([i, color]) => { ctx.strokeStyle = color; ctx.beginPath(); history.forEach((p, x) => { const px = x * cv.width / 120, py = cv.height - 4 - p[i] / max * (cv.height - 12); x ? ctx.lineTo(px, py) : ctx.moveTo(px, py); }); ctx.stroke(); });
      ctx.fillStyle = css.color; ctx.fillText(max.toFixed(2) + " Mbit/s", 4, 12);
      const p = history[history.length - 1] || [0, 0]; info.textContent = `Upload ${p[0].toFixed(2)} Mbit/s (red) · Download ${p[1].toFixed(2)} Mbit/s (blue) — from the server's view: TX is toward the client.`;
    } catch (error) {
      if (active() && cv.isConnected && error.message !== "login required") info.textContent = "Unavailable: " + error.message;
    } finally { sampling = false; }
  };
  sample(); cv._t = setInterval(sample, 2000); const stop = () => clearInterval(cv._t); window.addEventListener("hashchange", stop, { once: true });
}

async function route() {
  const version = ++routeVersion, hash = location.hash;
  clearInterval(timer); timer = null;
  if (!csrf) return login();
  const active = () => version === routeVersion && hash === location.hash && csrf !== null;
  const [, , id = "overview"] = hash.split("/");
  if (hash === "#/logout") { await api("logout", {}); csrf = null; currentIdentity=null; location.hash = ""; return boot(); }
  $("notice").replaceChildren(); renderNav(id);
  const page = pages[id] || pages.overview, view = $("view");
  let drawing = false;
  const draw = async () => {
    if (!active() || drawing) return;
    drawing = true;
    try {
      const content = await page(active);
      if (active()) view.replaceChildren(...content);
    } catch (error) {
      if (active() && error.message !== "login required") view.replaceChildren(err(error.message));
    } finally { drawing = false; }
  };
  await draw();
  if (!active()) return;
  const live = ["overview", "uplinks", "queues", "devices", "server-network"].includes(id); $("refresh").hidden = !live;
  if (live) timer = setInterval(draw, 5000);
}

async function boot() {
  const s = (await api("session")).data; csrf = s.authenticated ? s.csrf : null; currentIdentity=s.identity||null;
  $("refresh").hidden = true; renderNav(); route();
}
window.addEventListener("hashchange", route);
boot();
