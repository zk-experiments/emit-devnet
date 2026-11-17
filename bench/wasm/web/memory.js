// Observe only this worker's exported/imported linear memories. This is not RSS.
export function observeWasmMemory() {
  const memories=new Set(), NativeMemory=WebAssembly.Memory, NativeInstance=WebAssembly.Instance;
  const remember=value=>{if(value instanceof NativeMemory)memories.add(value);};
  const imports=object=>{for(const namespace of Object.values(object??{}))for(const value of Object.values(namespace??{}))remember(value);};
  const instance=value=>{for(const exported of Object.values(value.exports))remember(exported);};
  WebAssembly.Memory=new Proxy(NativeMemory,{construct(target,args){const value=Reflect.construct(target,args);remember(value);return value;}});
  WebAssembly.Instance=new Proxy(NativeInstance,{construct(target,args){imports(args[1]);const value=Reflect.construct(target,args);instance(value);return value;}});
  for(const name of ['instantiate','instantiateStreaming']) {
    const original=WebAssembly[name];if(!original)continue;
    WebAssembly[name]=async(...args)=>{imports(args[1]);const value=await original.apply(WebAssembly,args);instance(value instanceof NativeInstance?value:value.instance);return value;};
  }
  return()=>({bytes:memories.size?[...memories].reduce((sum,memory)=>sum+memory.buffer.byteLength,0):null,instances:memories.size,method:'retained observed WASM capacity; excludes JS/native overhead and unobserved nested-worker memories'});
}
