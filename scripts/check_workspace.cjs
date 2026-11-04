/* Browser acceptance checks. Run only against an isolated test server.
   Requires playwright, CORROBORA_E2E_URL, CORROBORA_E2E_USERNAME, CORROBORA_E2E_PASSWORD.
   Set CORROBORA_E2E_ALLOW_BOOTSTRAP=1 only on a disposable first-run database. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.CORROBORA_PLAYWRIGHT_MODULE || 'playwright');
const url = process.env.CORROBORA_E2E_URL;
const username = process.env.CORROBORA_E2E_USERNAME;
const password = process.env.CORROBORA_E2E_PASSWORD;
if (!url || !username || !password) throw new Error('Set the three CORROBORA_E2E_* connection variables for an isolated test server.');
const output = path.resolve(process.env.CORROBORA_E2E_OUTPUT || 'output/workspace-check');
fs.mkdirSync(output,{recursive:true});

(async()=>{
  const browser = await chromium.launch({headless:true});
  const page = await browser.newPage({viewport:{width:1440,height:1080},colorScheme:'light'});
  const errors = [], checks = [];
  page.on('pageerror', error=>errors.push(error.message));
  const check = (name, condition=true) => { assert.ok(condition,name); checks.push(name); console.log('PASS',name); };
  try {
    await page.goto(url);
    await page.locator('#auth-overlay:not(.hidden)').waitFor();
    await page.screenshot({path:path.join(output,'login.png')});
    if ((await page.locator('#auth-title').innerText()).includes('First Admin')) {
      assert.equal(process.env.CORROBORA_E2E_ALLOW_BOOTSTRAP,'1','Bootstrap requires an explicitly disposable server');
    }
    await page.locator('#auth-username').fill(username);
    await page.locator('#auth-password').fill(password);
    await page.locator('#auth-submit').click();
    await page.locator('#auth-overlay').waitFor({state:'hidden'});
    await page.locator('#stats-row .stat').first().waitFor();
    check('Login and real API overview render');
    check('Navigation title remains visible', await page.locator('#page-title').isVisible());
    check('Four live metric cards',await page.locator('#stats-row .stat').count()===4);
    await page.screenshot({path:path.join(output,'overview-light.png'),fullPage:true});

    let preferenceWrites=0;
    page.on('request',request=>{if(request.url().endsWith('/api/auth/preferences')&&request.method()==='PATCH') preferenceWrites++;});
    await page.evaluate(()=>loadCases(true));
    await page.evaluate(()=>loadCases(true));
    await page.waitForTimeout(700);
    check('Unchanged background refresh does not write preferences',preferenceWrites===0);
    await page.keyboard.press('/');
    check('Search shortcut focuses case search',await page.locator('#cases-search').evaluate(el=>el===document.activeElement));
    await page.locator('#cases-search').fill('no-such-investigation-acceptance');
    check('Case search shows useful empty state',(await page.locator('#cases-table').innerText()).includes('No investigations match'));
    await page.locator('#cases-search').fill('');
    await page.locator('#cases-status').selectOption('failed');
    await page.locator('#cases-status').selectOption('');
    check('Case status filter operates');

    await page.getByRole('button',{name:'My queue ↗',exact:true}).click();
    check('Overview queue shortcut navigates to the queue',await page.locator('#page-queue').isVisible());
    await page.getByRole('button',{name:'Clear Filters',exact:true}).click();

    await page.getByRole('button',{name:'Review queue',exact:true}).click();
    await page.locator('#queue-stats .stat').first().waitFor();
    await page.locator('#queue-search').fill('no-such-review-acceptance');
    check('Review search shows no-match state',(await page.locator('#queue-table').innerText()).includes('No queue items'));
    await page.getByRole('button',{name:'Clear Filters',exact:true}).click();
    check('Clear Filters resets text search',await page.locator('#queue-search').inputValue()==='');
    await page.screenshot({path:path.join(output,'review-queue.png'),fullPage:true});
    await page.getByRole('button',{name:'Overview',exact:true}).click();
    await page.locator('#cases-table a').first().waitFor();
    const caseName = await page.locator('#cases-table a').first().innerText();
    await page.locator('#cases-table a').first().click();
    await page.getByRole('button',{name:'Timeline',exact:true}).waitFor();
    check('Case evidence detail opens',await page.locator('#detail-case-name').innerText()===caseName);
    await page.getByRole('button',{name:'Timeline',exact:true}).click();
    await page.locator('#timeline-search').waitFor();
    check('Real timeline API renders',await page.locator('.timeline-entry').count()>0);
    await page.locator('.timeline-entry summary').first().click();
    check('Timeline evidence can be expanded',await page.locator('.timeline-entry[open]').count()===1);
    await page.locator('#timeline-search').fill('no-such-evidence-acceptance');
    check('Timeline search filters evidence',await page.locator('.timeline-entry').count()===0);
    await page.locator('#timeline-search').fill('');
    const hostOptions = await page.locator('#timeline-host option').count();
    if(hostOptions>1){await page.locator('#timeline-host').selectOption({index:1});check('Host filter narrows timeline');await page.locator('#timeline-host').selectOption('');}
    await page.screenshot({path:path.join(output,'timeline.png'),fullPage:true});

    // Delayed text response must never replace a subsequently selected evidence tab.
    await page.route('**/api/cases/*/summary',async route=>{await new Promise(resolve=>setTimeout(resolve,500));await route.fulfill({json:{summary:'STALE SUMMARY MARKER'}});});
    await page.getByRole('button',{name:'Summary',exact:true}).click();
    await page.getByRole('button',{name:'Overview',exact:true}).last().click();
    await page.waitForTimeout(650);
    check('Late summary response cannot overwrite active tab',!(await page.locator('#detail-content').innerText()).includes('STALE SUMMARY MARKER'));
    await page.unroute('**/api/cases/*/summary');

    const escaping = await page.evaluate(()=>{
      const payload = "case' onclick='window.__unsafe=true' <>&\"";
      const holder = document.createElement('div');
      holder.innerHTML = `<button onclick='window.__escapedValue=${jsv(payload)}'>${esc(payload)}</button>`;
      holder.firstChild.click();
      return window.__escapedValue===payload && !window.__unsafe && holder.firstChild.attributes.length===1;
    });
    check('Untrusted quotes and markup stay inert in inline arguments',escaping);
    await page.getByRole('button',{name:'Overview',exact:true}).first().click();
    await page.waitForFunction(()=>!casesLoading);
    await page.route('**/api/cases',route=>route.fulfill({status:503,json:{detail:'Acceptance outage'}}));
    await page.evaluate(()=>loadCases(true));
    check('Refresh outage preserves evidence and shows stale state',await page.locator('#workspace-error').isVisible() && await page.locator('#cases-table a').count()>0);
    await page.unroute('**/api/cases');
    await page.evaluate(()=>loadCases());
    check('Refresh recovers after outage',await page.locator('#workspace-error').count()===0);

    await page.locator('#btn-open-preferences').click();
    await page.locator('#preferences-modal:not(.hidden)').waitFor();
    check('Modal makes background inert',await page.locator('.shell').evaluate(el=>el.inert));
    await page.keyboard.press('Escape');
    check('Escape closes preferences',!await page.locator('#preferences-modal').isVisible());
    await page.evaluate(()=>{userPreferences.themeMode='dark';applyThemePreference();});
    await page.screenshot({path:path.join(output,'overview-dark.png'),fullPage:true});
    check('Dark theme applies',await page.locator('body').evaluate(el=>el.classList.contains('theme-dark')));
    await page.evaluate(()=>{userPreferences.themeMode='light';applyThemePreference();});
    await page.setViewportSize({width:390,height:844});
    check('Mobile layout has no page overflow',await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    await page.locator('.mobile-menu').click();
    check('Mobile navigation opens',await page.locator('#workspace-nav').isVisible());
    await page.getByRole('button',{name:'Review queue',exact:true}).click();
    check('Mobile navigation selects page and closes',!await page.locator('#workspace-nav').isVisible()&&await page.locator('#page-queue').isVisible());
    check('Mobile queue does not overflow page',await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    await page.screenshot({path:path.join(output,'mobile-queue.png'),fullPage:true});
    await page.locator('.mobile-menu').click();
    await page.getByRole('button',{name:'Overview',exact:true}).click();
    await page.screenshot({path:path.join(output,'mobile-overview.png'),fullPage:true});
    await page.locator('.mobile-menu').click();
    await page.locator('#btn-sidebar-logout').click();
    await page.locator('#auth-overlay:not(.hidden)').waitFor();
    check('Logout clears cached evidence',await page.locator('#cases-table a').count()===0);
    check('No uncaught browser exceptions',errors.length===0);
    fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({passed:true,checks,errors},null,2));
  }catch(error){fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({passed:false,checks,errors,failure:String(error)},null,2));await page.screenshot({path:path.join(output,'failure.png'),fullPage:true});throw error;}
  finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
