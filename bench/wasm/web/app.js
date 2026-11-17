import { styles, renderTable } from '../report-view.mjs';
const style=document.createElement('style');style.textContent=styles;document.head.append(style);
const $=id=>document.getElementById(id);
const base=new URL('./',location.href).href;
const report={metadata:{runtime:'browser',user_agent:navigator.userAgent,logical_cores:navigator.hardwareConcurrency??1,secure_context:isSecureContext,cross_origin_isolated:crossOriginIsolated},circuits:{},runs:[],verifications:[]};
let manifest,running=false,worker,cancel;
const status=text=>{$('status').textContent=text;};
const render=()=>{$('summary').innerHTML=renderTable(report);$('raw').textContent=JSON.stringify(report,null,2);$('export').disabled=!report.runs.length;};
$('environment').textContent=`${navigator.userAgent} · ${report.metadata.logical_cores} logical cores`;
function sample(entry,threads,verifyOnly=false){return new Promise((resolve,reject)=>{
  worker=new Worker(new URL('./worker.js',import.meta.url),{type:'module'});
  cancel=()=>{worker.terminate();reject(new Error('Cancelled by user'));};
  worker.onerror=event=>reject(new Error(event.message||'Worker failed; possible memory limit'));
  worker.onmessage=({data})=>{if(data.type==='phase')status(`${entry.pipeline} / ${entry.backend}: ${data.label}`);else if(data.type==='result')resolve(data.result);};
  worker.postMessage({entry,threads,base,verifyOnly,count:20});
});}
$('controls').onsubmit=async event=>{
  event.preventDefault();if(running)return;
  const chosen=name=>[...document.querySelectorAll(`input[name=${name}]:checked`)].map(i=>i.value);
  const pipelines=chosen('pipeline'),backends=chosen('backend'),threads=$('threads').value.split(',').map(Number),count=Number($('samples').value);
  if(!pipelines.length||!backends.length||!Number.isInteger(count)||count<1||count>20){status('Choose workloads, implementations and a valid sample count.');return;}
  running=true;$('run').disabled=true;$('stop').disabled=false;report.metadata.device_label=$('device').value;report.metadata.date=new Date().toISOString();
  report.metadata.samples=count;report.metadata.threads=threads;report.metadata.verify_warmups=1;report.metadata.verify_samples=20;
  for(const pipeline of pipelines)for(const backend of backends){
    if(!running)break;
    const entry=manifest.entries.find(e=>e.pipeline===pipeline&&e.backend===backend);
    if(!entry){report.runs.push({pipeline,backend,threads:threads[0],status:'error',error:'Artifacts not prepared'});render();continue;}
    for(const threadCount of threads)for(let i=1;i<=count&&running;i++){
      let backgrounded=document.hidden;const visibility=()=>{backgrounded ||= document.hidden;};document.addEventListener('visibilitychange',visibility);
      try{report.runs.push({...await sample(entry,threadCount),sample:i,backgrounded});}
      catch(error){report.runs.push({pipeline,backend,threads:threadCount,sample:i,status:'error',error:error.message,backgrounded});}
      finally{document.removeEventListener('visibilitychange',visibility);worker?.terminate();worker=null;cancel=null;}render();
    }
    if(running&&$('full').checked){
      let wasm;
      try{wasm=await sample(entry,report.metadata.logical_cores,true);}catch(error){wasm={status:'error',error:error.message};}
      finally{worker?.terminate();worker=null;cancel=null;}
      report.verifications.push({pipeline,backend,wasm,native:null});render();
    }
  }
  const stopped=!running;running=false;$('run').disabled=false;$('stop').disabled=true;
  status(stopped?'Stopped; completed results retained.':`Finished. ${report.runs.filter(r=>r.status==='ok').length}/${report.runs.length} successful proving samples. Failures remain visible.`);
};
$('stop').onclick=()=>{running=false;cancel?.();};
$('export').onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=`passport-comparison-${new Date().toISOString().replaceAll(':','-')}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
try{
  const response=await fetch('./manifest.json');if(!response.ok)throw new Error('Prepare artifacts and build the browser demo first');manifest=await response.json();
  report.metadata.source=manifest.source;report.circuits=manifest.circuits;
  $('manifest').textContent=JSON.stringify(manifest,null,2);
  $('reference').hidden=!manifest.reference;
  $('native-reference').hidden=!manifest.native_reference;
  if(!isSecureContext)throw new Error('Use HTTPS or localhost for integrity checks');
  $('run').disabled=false;status('Ready. Start with age verification before the memory-intensive registration cases.');render();
}catch(error){status(error.message);}
