import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const out=fileURLToPath(new URL('../results/browser-comparison/',import.meta.url));await mkdir(out,{recursive:true});
const browser=await chromium.launch({channel:'chrome',headless:true});
try{
  const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto(process.env.DEMO_URL??'http://localhost:8090');
  await page.waitForFunction(()=>!document.getElementById('run').disabled,{}, {timeout:30000});
  await page.locator('#device').fill('Desktop Chrome smoke; not a phone result');
  await page.locator('#run').click();
  await page.waitForFunction(()=>!document.getElementById('run').disabled,{}, {timeout:1800000});
  const report=JSON.parse(await page.locator('#raw').textContent());console.log(JSON.stringify(report.runs,null,2));
  assert.equal(report.runs.length,6);
  for(const run of report.runs){assert.equal(run.status,'ok',`${run.backend}/${run.threads}: ${run.error}`);assert.equal(run.verified,true);assert.ok(run.prove_ms>0&&run.verify_ms>0&&run.proof_bytes>0);}
  assert.equal(report.verifications.length,3);
  for(const verification of report.verifications){assert.equal(verification.wasm.status,'ok',verification.wasm.error);assert.equal(verification.wasm.verify_samples_ms.length,20);}
  const downloading=page.waitForEvent('download');await page.locator('#export').click();await(await downloading).saveAs(out+'observations.json');
  assert.equal(JSON.parse(await readFile(out+'observations.json','utf8')).runs.length,6);
  await page.screenshot({path:out+'desktop.png',fullPage:true});await page.setViewportSize({width:390,height:844});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await page.screenshot({path:out+'narrow.png'});assert.deepEqual(errors,[]);
  console.log('PASS: shared age logic, all3 WASM implementations,1/6 threads, full-device verification, export and responsive layout.');
}finally{await browser.close();}
