// Resource data comes from a cached authenticated endpoint. Opening this page
// never changes the server or triggers extra OS sampling.
NAV[0][1].splice(4,0,['hardware','Hardware Resources']);
pages.hardware=async function(active=()=>true){
  const root=h('section',{},h('h2',{},'Hardware Resources'),h('p',{class:'muted'},'OS-visible resources sampled in the server process; container namespaces can limit what is visible.'));
  const status=h('p',{class:'muted'}),summary=h('div',{}),graphs=h('div',{}),details=h('div',{});
  root.append(status,summary,graphs,details);
  const chart=(title)=>{const canvas=h('canvas',{width:900,height:200,'aria-label':title});graphs.append(h('h3',{},title),canvas);return canvas;};
  const cpuChart=chart('CPU and memory (%)'),diskChart=chart('Disk throughput (bytes/s)');
  function plot(canvas,history,series,minimum){
    const ctx=canvas.getContext('2d'),w=canvas.width,hg=canvas.height;
    ctx.clearRect(0,0,w,hg);const ceiling=Math.max(minimum,...history.flatMap(row=>series.map(([key])=>row[key]||0)))*1.05;
    for(const [key,color]of series){ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();let started=false;
      for(let i=0;i<history.length;i++){const v=history[i][key];if(v==null){started=false;continue}const x=12+i*(w-24)/Math.max(1,history.length-1),y=hg-18-v/ceiling*(hg-34);if(started)ctx.lineTo(x,y);else ctx.moveTo(x,y);started=true}ctx.stroke();}
    ctx.fillStyle='#888';ctx.font='12px sans-serif';ctx.fillText(ceiling.toFixed(1),12,13);
  }
  async function read(){
    const response=await api('hardware');if(!response.ok)throw Error(response.data.error||'Hardware endpoint unavailable');return response.data;
  }
  function render(d){
    status.textContent=d.available===false?(d.status==='warming_up'?'Preparing the first resource sample…':(d.errors||['Hardware monitoring unavailable']).join('; ')):'Updated '+new Date(d.observed_at*1000).toLocaleString()+' · '+(d.platform||'server');
    status.className=d.available===false?'bad':'muted';
    if(d.available===false){summary.replaceChildren();details.replaceChildren();plot(cpuChart,[],[],100);plot(diskChart,[],[],1);return}
    const percent=v=>v==null?'—':Number(v).toFixed(1)+' %';
    const diskRates=Object.values(d.disk_io||{}).map(row=>row.rates).filter(Boolean);
    summary.replaceChildren(kv([['CPU',percent(d.cpu?.percent)],['Logical processors',d.cpu?.logical_processors??'—'],['Memory',fmtBytes(d.memory?.used_bytes)+' / '+fmtBytes(d.memory?.total_bytes)+' · '+percent(d.memory?.percent)],['Swap',fmtBytes(d.swap?.used_bytes)+' / '+fmtBytes(d.swap?.total_bytes)],['Disk read',diskRates.length?fmtBytes(diskRates.reduce((n,r)=>n+r.read_bytes,0))+'/s':'—'],['Disk write',diskRates.length?fmtBytes(diskRates.reduce((n,r)=>n+r.write_bytes,0))+'/s':'—'],['GPU',d.gpu?.percent==null?(d.gpu?.status||'unavailable'):percent(d.gpu.percent)]]));
    plot(cpuChart,d.history||[],[['cpu_percent','#009dcc'],['memory_percent','#e1aa20']],100);
    plot(diskChart,d.history||[],[['disk_read_bytes_s','#009dcc'],['disk_write_bytes_s','#e1aa20']],1);
    const coverage=d.process_coverage||{};
    details.replaceChildren(h('h3',{},'Processes'),h('p',{class:'muted'},'CPU is normalized to total logical CPU capacity. Examined '+(coverage.examined??0)+'; inaccessible '+(coverage.inaccessible??0)+(coverage.scan_limit_reached?' · scan limit reached':'')),grid(['Application','PID','CPU','Memory','Threads'],(d.processes||[]).map(p=>[p.name,p.pid,percent(p.cpu_percent),fmtBytes(p.resident_bytes),p.threads??'—'])),h('h3',{},'Disks'),grid(['Mount','Used','Free','Usage'],(d.disks||[]).map(p=>[p.mountpoint||p.device,fmtBytes(p.used_bytes),fmtBytes(p.free_bytes),p.error||percent(p.percent)])),h('h3',{},'Adapters'),grid(['Name','State','Receive','Send'],(d.adapters||[]).map(p=>[p.name,p.up?'Up':'Down',p.rates?fmtBytes(p.rates.received_bytes)+'/s':'—',p.rates?fmtBytes(p.rates.sent_bytes)+'/s':'—'])));
    if(d.errors?.length)details.append(h('p',{class:'bad'},d.errors.join('; ')));
  }
  render(await read());
  async function refresh(){
    if(!active()||!root.isConnected)return;
    try{const d=await read();if(active()&&root.isConnected)render(d)}catch(e){if(active())status.textContent=e.message}
    if(active()&&root.isConnected)setTimeout(refresh,2000);
  }
  setTimeout(refresh,2000);return[root];
};
if(csrf)renderNav(location.hash.split('/')[2]||'overview');
