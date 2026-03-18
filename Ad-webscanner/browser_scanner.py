"""
Browser automation for scanning dynamic/SPA content
Uses Playwright for headless browser control
"""

import asyncio
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from playwright.async_api import async_playwright, Browser, Page, BrowserContext

logger = logging.getLogger(__name__)

@dataclass
class SPAFindings:
    """Container for SPA vulnerability findings"""
    xss_vulnerabilities: List[Dict]
    api_endpoints: List[str]
    dom_sinks: List[Dict]
    js_errors: List[str]
    cookies: Dict
    storage: Dict
    tech_stack: List[str]
    error: Optional[str] = None

class BrowserScanner:
    """
    Headless browser automation for SPA/dynamic content vulnerability scanning
    
    Features:
    - JavaScript execution and dynamic content detection
    - DOM-based XSS discovery
    - API endpoint extraction via network interception
    - Client-side storage inspection
    - Cookie analysis
    - JavaScript error detection
    
    Usage:
        scanner = BrowserScanner()
        await scanner.initialize()
        findings = await scanner.scan_spa_vulnerabilities("https://example.com")
        await scanner.close()
    """
    
    def __init__(
        self,
        timeout: int = 30000,  # milliseconds
        headless: bool = True,
        slow_mo: int = 0,
        args: Optional[List[str]] = None
    ):
        """
        Initialize browser scanner configuration.
        
        Args:
            timeout: Navigation timeout in milliseconds
            headless: Run in headless mode (no GUI)
            slow_mo: Slow down operations by N milliseconds
            args: Additional browser arguments (e.g., ['--no-sandbox'])
        """
        self.timeout = timeout
        self.headless = headless
        self.slow_mo = slow_mo
        self.browser_args = args or ['--no-sandbox', '--disable-setuid-sandbox']
        
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.intercepted_requests: Set[str] = set()
    
    async def initialize(self):
        """Launch headless browser and prepare for scanning"""
        try:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=self.headless,
                slow_mo=self.slow_mo,
                args=self.browser_args
            )
            logger.info("✅ Browser initialized successfully")
        except Exception as e:
            logger.error(f"❌ Failed to initialize browser: {e}")
            raise
    
    async def close(self):
        """Clean up browser resources"""
        try:
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            logger.info("✅ Browser closed and cleaned up")
        except Exception as e:
            logger.error(f"⚠️ Error closing browser: {e}")
    
    async def scan_spa_vulnerabilities(
        self, 
        url: str,
        test_xss: bool = True,
        extract_apis: bool = True,
        check_storage: bool = True
    ) -> SPAFindings:
        """
        Scan Single Page Application for vulnerabilities.
        
        Args:
            url: Target URL
            test_xss: Perform DOM XSS testing
            extract_apis: Extract API endpoints via network interception
            check_storage: Inspect localStorage/sessionStorage
            
        Returns:
            SPAFindings with all detected vulnerabilities and data
        """
        if not self.browser:
            raise RuntimeError("Browser not initialized. Call initialize() first.")
        
        page = await self.browser.new_page()
        findings = SPAFindings(
            xss_vulnerabilities=[],
            api_endpoints=[],
            dom_sinks=[],
            js_errors=[],
            cookies={},
            storage={},
            tech_stack=[]
        )
        
        try:
            # Setup request interception
            api_calls = []
            
            async def handle_response(response):
                """Capture API calls"""
                if response.request.method in ['GET', 'POST', 'PUT', 'DELETE']:
                    if any(pattern in response.url for pattern in ['api', 'graphql', 'ajax']):
                        api_calls.append({
                            'url': response.url,
                            'method': response.request.method,
                            'status': response.status,
                            'type': response.request.post_data_json if response.request.post_data else None
                        })
            
            page.on('response', handle_response)
            
            # Collect JS errors
            page.on('console', lambda msg: 
                findings.js_errors.append(f"[{msg.type}] {msg.text}") if msg.type == 'error' else None
            )
            
            logger.info(f"🌐 Navigating to {url}...")
            try:
                await page.goto(url, wait_until='networkidle', timeout=self.timeout)
            except:
                # Continue even if timeout (page partially loaded is useful)
                logger.warn(f"⚠️ Navigation timed out, continuing with partial page...")
            
            # Extract API endpoints
            if extract_apis:
                logger.info("📡 Extracting API endpoints...")
                findings.api_endpoints = list(set([call['url'] for call in api_calls]))
                logger.info(f"✅ Found {len(findings.api_endpoints)} API endpoints")
            
            # Test for DOM XSS
            if test_xss:
                logger.info("🎯 Testing for DOM-based XSS...")
                findings.xss_vulnerabilities = await self._test_dom_xss(page, url)
                logger.info(f"✅ XSS test complete: {len(findings.xss_vulnerabilities)} vulnerabilities found")
            
            # Extract cookies
            cookies = await page.context.cookies()
            findings.cookies = {c['name']: c['value'] for c in cookies}
            logger.info(f"✅ Extracted {len(findings.cookies)} cookies")
            
            # Get localStorage/sessionStorage
            if check_storage:
                logger.info("💾 Inspecting client-side storage...")
                try:
                    storage_data = await page.evaluate('''
                        () => {
                            return {
                                localStorage: Array.from({length: localStorage.length}, (_, i) => ({
                                    key: localStorage.key(i),
                                    value: localStorage.getItem(localStorage.key(i))
                                })),
                                sessionStorage: Array.from({length: sessionStorage.length}, (_, i) => ({
                                    key: sessionStorage.key(i),
                                    value: sessionStorage.getItem(sessionStorage.key(i))
                                }))
                            };
                        }
                    ''')
                    findings.storage = storage_data
                    logger.info(f"✅ Found {len(storage_data.get('localStorage', []))} localStorage items")
                except Exception as e:
                    logger.warn(f"⚠️ Could not inspect storage: {e}")
            
            # Detect tech stack via JavaScript frameworks
            logger.info("🔍 Detecting tech stack...")
            tech_detected = await self._detect_tech_stack(page)
            findings.tech_stack = tech_detected
            logger.info(f"✅ Detected technologies: {', '.join(tech_detected)}")
            
        except Exception as e:
            logger.error(f"❌ SPA scan failed: {e}")
            findings.error = str(e)
        
        finally:
            await page.close()
        
        return findings
    
    async def _test_dom_xss(self, page: Page, base_url: str) -> List[Dict]:
        """
        Test for DOM-based XSS vulnerabilities
        
        Injects payloads and checks if they execute
        """
        vulnerabilities = []
        
        test_cases = [
            {
                'name': 'Image onerror',
                'payload': '<img src=x onerror="window.__xss_test=true">',
                'check': 'window.__xss_test'
            },
            {
                'name': 'SVG onload',
                'payload': '<svg onload="window.__xss_test2=1">',
                'check': 'window.__xss_test2'
            },
            {
                'name': 'Alert payload',
                'payload': '<script>window.__xss_alert=true</script>',
                'check': 'window.__xss_alert'
            }
        ]
        
        for test_case in test_cases:
            try:
                # Try different injection points
                injection_points = [
                    f"{base_url}?q={test_case['payload']}",
                    f"{base_url}?search={test_case['payload']}",
                    f"{base_url}?id={test_case['payload']}",
                ]
                
                for test_url in injection_points:
                    try:
                        await page.goto(test_url, wait_until='domcontentloaded', timeout=5000)
                        
                        # Check if payload executed
                        result = await page.evaluate(f"() => {test_case['check']} === true || {test_case['check']} === 1")
                        
                        if result:
                            vulnerabilities.append({
                                'type': 'DOM XSS',
                                'test': test_case['name'],
                                'parameter': test_url.split('=', 1)[0].split('?', 1)[1],
                                'severity': 'High',
                                'payload': test_case['payload']
                            })
                            break
                    except:
                        continue
                        
            except Exception as e:
                logger.debug(f"XSS test '{test_case['name']}' encountered: {e}")
        
        return vulnerabilities
    
    async def _detect_tech_stack(self, page: Page) -> List[str]:
        """
        Detect technologies used in the application
        """
        detected = []
        
        # Check for common frameworks via JavaScript globals
        checks = {
            'React': 'window.React !== undefined',
            'Vue.js': 'window.Vue !== undefined || window.__VUE__ !== undefined',
            'Angular': 'window.angular !== undefined || document.ng-app !== null',
            'jQuery': 'window.jQuery !== undefined || window.$ !== undefined',
            'Bootstrap': 'document.querySelector("[data-bs-version]") !== null',
            'Tailwind': 'document.querySelector("html").classList.contains("tw-") || true',  # Tailwind uses inline styles
            'Next.js': 'window.__NEXT_DATA__ !== undefined',
            'Nuxt.js': 'window.__NUXT__ !== undefined',
            'Svelte': 'window.Svelte !== undefined',
        }
        
        try:
            for tech, check_code in checks.items():
                try:
                    is_present = await page.evaluate(f"() => {{{check_code}}}")
                    if is_present:
                        detected.append(tech)
                except:
                    pass
        except Exception as e:
            logger.debug(f"Tech detection error: {e}")
        
        return detected
    
    async def screenshot(self, url: str, filename: str = "screenshot.png"):
        """Take screenshot of page for documentation"""
        page = await self.browser.new_page()
        try:
            await page.goto(url, wait_until='networkidle')
            await page.screenshot(path=filename)
            logger.info(f"✅ Screenshot saved to {filename}")
        finally:
            await page.close()
    
    async def get_page_content(self, url: str) -> str:
        """Get fully rendered page content (including JS-rendered content)"""
        page = await self.browser.new_page()
        try:
            await page.goto(url, wait_until='networkidle', timeout=self.timeout)
            
            # Wait for common SPA frameworks to finish rendering
            await asyncio.sleep(2)
            
            content = await page.content()
            return content
        finally:
            await page.close()
