"""
Build ChainSentry landing page by directly transforming the scraped WriteMate HTML.
Maintains 100% of WriteMate layout, Tailwind classes, and styling while updating
the branding, headlines, hero CTA, ecosystem bar, and supply chain security text.
"""

import re

def main():
    with open("frontend/scraped_writemate.html", "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Update title and link CSS
    html = html.replace(
        "WriteMate AI - Content Creation at Its Best",
        "ChainSentry — Software Supply Chain Security & AI Auto-Remediation"
    )
    html = html.replace('href="/assets/index-CdLNTYUv.css"', 'href="/static/writemate.css"')
    html = html.replace('src="/assets/index-DA8RDcsB.js"', 'src="/static/landing.js"')

    # 2. Update Logo and brand in header
    old_logo = '<a href="/" data-discover="true"><img alt="WriteMate AI Logo" src="/images/logo.svg"></a>'
    new_logo = '''<a href="/" class="flex items-center gap-2 group">
        <svg width="19" height="19" viewBox="0 0 19 19" fill="none" xmlns="http://www.w3.org/2000/svg" class="transition-transform group-hover:scale-105 duration-200">
            <rect x="0.75" y="0.75" width="17.5" height="17.5" rx="4" stroke="white" stroke-width="1.5"/>
        </svg>
        <span class="text-white font-bold text-xl tracking-tight leading-none" style="font-family: -apple-system, BlinkMacSystemFont, 'Inter', sans-serif;">ChainSentry</span>
        <span class="text-white/60 font-normal text-xl leading-none" style="font-family: -apple-system, BlinkMacSystemFont, 'Inter', sans-serif;">AI</span>
    </a>'''
    if old_logo in html:
        html = html.replace(old_logo, new_logo, 1)

    # 3. Update Nav Links
    old_nav = '<li><a class="transition-colors duration-300 text-white" href="/" data-discover="true">Home</a></li><li><a class="transition-colors duration-300 text-white/60" href="/pricing" data-discover="true">Pricing</a></li><li><a class="transition-colors duration-300 text-white/60" href="/docs" data-discover="true">Docs</a></li><li><a class="transition-colors duration-300 text-white/60" href="/support" data-discover="true">Support</a></li>'
    new_nav = '<ul style="display: flex; align-items: center; gap: 36px; list-style: none; margin: 0; padding: 0;"><li><a class="transition-colors duration-300 text-white font-medium hover:text-white" style="font-size: 15px; text-decoration: none; padding: 6px 0; display: inline-block;" href="#capabilities">Capabilities</a></li><li><a class="transition-colors duration-300 text-white/60 hover:text-white" style="font-size: 15px; text-decoration: none; padding: 6px 0; display: inline-block;" href="#ecosystems">Ecosystems</a></li><li><a class="transition-colors duration-300 text-white/60 hover:text-white" style="font-size: 15px; text-decoration: none; padding: 6px 0; display: inline-block;" href="#use-cases">Use Cases</a></li><li><a class="transition-colors duration-300 text-white/60 hover:text-white" style="font-size: 15px; text-decoration: none; padding: 6px 0; display: inline-block;" href="#faq">FAQ</a></li><li><a class="transition-colors duration-300 text-white/60 hover:text-white" style="font-size: 15px; text-decoration: none; padding: 6px 0; display: inline-block;" href="/docs" target="_blank">API Docs</a></li></ul>'
    if old_nav in html:
        html = html.replace(old_nav, new_nav, 1)

    # 4. Header: remove Start button and dashboard button completely from navbar
    old_buttons = '<div class=" sm:flex items-center"><div class="lg:flex hidden"><a class="cursor-pointer relative overflow-hidden group inline-flex items-center justify-center font-mono hidden sm:inline-flex text-base px-6 py-3.5 ring ring-transparent font-medium -tracking-[0.2px] leading-5 text-white    transition-all duration-300" href="/pricing" data-discover="true"><span class="block relative h-full w-full overflow-hidden"><span class="flex h-full w-full items-center justify-center" style="transform: none;">Login</span><span class="absolute top-0 left-0 w-full h-full flex items-center justify-center" style="transform: translateY(100%);">Login</span></span></a><a class="cursor-pointer relative overflow-hidden group inline-flex items-center justify-center font-mono hidden px-6 ring ring-white/40 sm:inline-flex text-base font-medium -tracking-[0.2px] leading-5 text-white py-3.5 hover:bg-white/10 transition-all duration-300" href="/pricing" data-discover="true"><span class="block relative h-full w-full overflow-hidden"><span class="flex h-full w-full items-center justify-center" style="transform: none;">Start for free</span><span class="absolute top-0 left-0 w-full h-full flex items-center justify-center" style="transform: translateY(100%);">Start for free</span></span></a></div>'
    new_buttons = ''
    if old_buttons in html:
        html = html.replace(old_buttons, new_buttons, 1)

    # 5. Main Hero Headline & Subheadline
    old_h1 = '<h1 class="text-4xl lg:text-5xl -tracking-[1.5px] xl:text-6xl font-normal text-white text-center xl:leading-16 mb-6" style="opacity: 1; transform: none;">Write Better. Reply Faster. Understand Anything with AI.</h1>'
    new_h1 = '<h1 class="text-4xl lg:text-5xl -tracking-[1.5px] xl:text-6xl font-normal text-white text-center xl:leading-16 mb-6" style="opacity: 1; transform: none;">Scan Smarter. Patch Faster.<br><span class="text-transparent bg-clip-text bg-gradient-to-r from-white via-blue-200 to-blue-400">Secure Every Dependency.</span></h1>'
    if old_h1 in html:
        html = html.replace(old_h1, new_h1, 1)

    old_sub = '<p class="text-white/80 text-base max-w-lg text-center mx-auto mb-8 xl:mb-14" style="opacity: 1; transform: none;">Your all-in-one AI writing platform — generate copy, summarize PDFs, write emails, and transform tone instantly.</p>'
    new_sub = '<p class="text-white/80 text-base max-w-xl text-center mx-auto mb-8 xl:mb-12" style="opacity: 1; transform: none;">Your all-in-one software supply chain security analyzer — identify risky dependencies, typosquatting indicators, build provenance flaws, and synthesize 1-click AI remediation patches.</p>'
    if old_sub in html:
        html = html.replace(old_sub, new_sub, 1)

    # 6. Hero Input: Replace "Write a linkedin post about a new AI tool..." with primary Start button
    old_input_box = '<div class="relative max-w-[500px] mx-auto" style="opacity: 1; transform: none;"><input class="text-sm text-white placeholder:text-white/60 p-8 pl-6 pr-20 bg-theme-dark-500 h-16 w-full focus:outline-0" placeholder="Write a linkedin post about a new AI tool..." type="text"><div class="absolute right-2 size-12 top-1/2 -translate-y-1/2 z-10"><button class="cursor-pointer relative overflow-hidden group inline-flex items-center justify-center bg-white size-12 inline-flex items-center justify-center hover:bg-gray-100 transition duration-300"><span class="block relative h-full w-full overflow-hidden"><span class="flex h-full w-full items-center justify-center" style="transform: none;"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M11.9961 3.99902L11.9961 20.0004M6 9.99502L11.9998 3.99902L18 9.99502" stroke="#060606" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"></path></svg></span><span class="absolute top-0 left-0 w-full h-full flex items-center justify-center" style="transform: translateY(100%);"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M11.9961 3.99902L11.9961 20.0004M6 9.99502L11.9998 3.99902L18 9.99502" stroke="#060606" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"></path></svg></span></span></button></div></div>'

    new_input_box = '''<div class="flex justify-center items-center">
    <a href="/dashboard" class="cursor-pointer relative overflow-hidden group inline-flex items-center justify-center bg-white text-black font-mono text-base font-semibold px-8 py-4 hover:bg-gray-200 transition-all duration-300 gap-2.5 shadow-2xl hover:scale-[1.03] active:scale-[0.98]">
        <span>Start</span>
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M5 12H19M13 6L19 12L13 18" stroke="#060606" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </a>
</div>'''

    if old_input_box in html:
        html = html.replace(old_input_box, new_input_box, 1)

    # 7. Replace "Trusted by" with "Supported Ecosystems & Registries"
    old_trusted = '<span class="text-white font-mono">Trusted by</span>'
    new_trusted = '<span class="text-white font-mono uppercase tracking-wider text-sm">Supported Ecosystems &amp; Registries</span>'
    if old_trusted in html:
        html = html.replace(old_trusted, new_trusted, 1)

    ecosystems_bar = '''<div id="ecosystems" class="max-w-6xl mx-auto px-4">
    <div class="ecosystem-scroll-container">
        <!-- 1. npm -->
        <div class="ecosystem-card">
            <div class="w-10 h-10 mb-2 flex items-center justify-center">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white">
                    <path d="M1.5 8.25h21v7.5H12V18H7.5v-2.25H1.5V8.25zm16.5 6V9.75h-3v4.5h3zm-4.5-4.5h-1.5v4.5H12v-4.5zm-3 4.5h1.5V9.75H10.5v4.5zm-3-4.5H6v3H4.5V9.75H3v4.5h4.5V9.75z"/>
                </svg>
            </div>
            <span class="text-white font-mono font-bold text-sm">npm</span>
            <span class="text-white/50 text-xs mt-1">JavaScript/TS</span>
        </div>
        <!-- 2. PyPI -->
        <div class="ecosystem-card">
            <div class="w-10 h-10 mb-2 flex items-center justify-center">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white">
                    <path d="M11.91 1C6.27 1 6.64 3.45 6.64 3.45l.01 2.55h5.36v.76H4.25S1 6.38 1 12.04c0 5.65 2.84 5.45 2.84 5.45h1.7v-2.39s-.09-2.84 2.79-2.84h4.74s2.69.04 2.69-2.62V3.62S16.32 1 11.91 1zm-1.5 1.54a.97.97 0 1 1 0 1.94.97.97 0 0 1 0-1.94zm1.68 20.46c5.64 0 5.27-2.45 5.27-2.45l-.01-2.55h-5.36v-.76h7.76s3.25.38 3.25-5.28c0-5.65-2.84-5.45-2.84-5.45h-1.7v2.39s.09 2.84-2.79 2.84h-4.74s-2.69-.04-2.69 2.62v6.02s-.56 2.62 3.85 2.62zm1.5-1.54a.97.97 0 1 1 0-1.94.97.97 0 0 1 0 1.94z"/>
                </svg>
            </div>
            <span class="text-white font-mono font-bold text-sm">PyPI</span>
            <span class="text-white/50 text-xs mt-1">Python</span>
        </div>
        <!-- 3. Go -->
        <div class="ecosystem-card">
            <div class="w-10 h-10 mb-2 flex items-center justify-center">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white">
                    <path d="M1.98 12.63c0-3.32 2.37-6.07 5.76-6.07 2.14 0 3.73 1.05 4.6 2.53l-1.92 1.34c-.58-.94-1.48-1.52-2.68-1.52-2.02 0-3.41 1.63-3.41 3.72 0 2.09 1.39 3.72 3.41 3.72 1.37 0 2.31-.73 2.75-1.87h-2.9v-2.22h5.3v5.67h-2.18v-1.12c-.78.89-1.84 1.48-3.17 1.48-3.39 0-5.76-2.75-5.76-6.07zm14.47 0c0-3.32 2.45-6.07 5.86-6.07s5.86 2.75 5.86 6.07-2.45 6.07-5.86 6.07-5.86-2.75-5.86-6.07zm9.37 0c0-2.09-1.44-3.72-3.51-3.72s-3.51 1.63-3.51 3.72 1.44 3.72 3.51 3.72 3.51-1.63 3.51-3.72z"/>
                </svg>
            </div>
            <span class="text-white font-mono font-bold text-sm">Go</span>
            <span class="text-white/50 text-xs mt-1">go.mod / sum</span>
        </div>
        <!-- 4. Maven -->
        <div class="ecosystem-card">
            <div class="w-10 h-10 mb-2 flex items-center justify-center">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M18 8h1a4 4 0 0 1 0 8h-1"/>
                    <path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"/>
                    <line x1="6" y1="2" x2="6" y2="5"/>
                    <line x1="10" y1="2" x2="10" y2="5"/>
                    <line x1="14" y1="2" x2="14" y2="5"/>
                </svg>
            </div>
            <span class="text-white font-mono font-bold text-sm">Maven</span>
            <span class="text-white/50 text-xs mt-1">Java / pom.xml</span>
        </div>
        <!-- 5. Cargo -->
        <div class="ecosystem-card">
            <div class="w-10 h-10 mb-2 flex items-center justify-center">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
                    <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
                    <line x1="12" y1="22.08" x2="12" y2="12"/>
                </svg>
            </div>
            <span class="text-white font-mono font-bold text-sm">Cargo</span>
            <span class="text-white/50 text-xs mt-1">Rust</span>
        </div>
        <!-- 6. Packagist -->
        <div class="ecosystem-card">
            <div class="w-10 h-10 mb-2 flex items-center justify-center">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/>
                </svg>
            </div>
            <span class="text-white font-mono font-bold text-sm">Packagist</span>
            <span class="text-white/50 text-xs mt-1">PHP / Composer</span>
        </div>
        <!-- 7. NuGet -->
        <div class="ecosystem-card">
            <div class="w-10 h-10 mb-2 flex items-center justify-center">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="3" width="18" height="18" rx="2" stroke-width="2"/>
                    <path d="M8 12h8M12 8v8"/>
                </svg>
            </div>
            <span class="text-white font-mono font-bold text-sm">NuGet</span>
            <span class="text-white/50 text-xs mt-1">.NET / C#</span>
        </div>
        <!-- 8. RubyGems -->
        <div class="ecosystem-card">
            <div class="w-10 h-10 mb-2 flex items-center justify-center">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M6 3h12l4 6-10 12L2 9l4-6z"/>
                    <path d="M2 9h20M12 21 8 9l4-6 4 6-4 12z"/>
                </svg>
            </div>
            <span class="text-white font-mono font-bold text-sm">RubyGems</span>
            <span class="text-white/50 text-xs mt-1">Ruby / Gemfile</span>
        </div>
    </div>
</div>'''

    html = re.sub(
        r'<div class="w-full inline-flex flex-nowrap overflow-hidden mask-\[linear-gradient.*?</ul>\s*</div>',
        ecosystems_bar,
        html,
        count=1,
        flags=re.DOTALL
    )

    # 8. Update "What You Get" section
    html = html.replace(
        'Describe your idea — the AI creates pages, layout, copy, images and SEO meta. Edit visually, publish or export clean HTML/CSS.',
        'Advanced dependency reasoning, blast radius computation, known CVE correlation, and automated Git diff patch synthesis.'
    )

    html = html.replace('AI Blog Writer', 'Dependency Graph & Blast Radius')
    html = html.replace('Social Post Generator', 'Known CVE & GHSA Correlation')
    html = html.replace('SEO Content Writer', 'Typosquatting & Scope Shield')
    html = html.replace('Email Writer', '1-Click Auto-Remediation Patch')

    html = html.replace(
        'Fully WCAG 2.0 compliant, made with best a11y practices',
        'NetworkX graph reasoning computing transitive reach and blast radius for every package.'
    )
    html = html.replace(
        'href="/tools" data-discover="true"><span class="block relative h-full w-full overflow-hidden"><span class="flex h-full w-full items-center justify-center" style="transform: none;">Try now</span>',
        'href="/dashboard"><span class="block relative h-full w-full overflow-hidden"><span class="flex h-full w-full items-center justify-center" style="transform: none;">Try now</span>'
    )

    # 9. Update "Writemate AI Use Cases"
    html = html.replace('Writemate AI Use Cases', 'ChainSentry Security Use Cases')
    html = html.replace(
        'Harness AI to effortlessly create stunning content with AI-driven design, copy, images, and SEO optimization. Refine, publish, or export as clean HTML/CSS.',
        'Empower security engineers, DevOps, and developers to eliminate supply chain vulnerabilities before code reaches production.'
    )

    html = html.replace('Innovative product design', 'Monorepo & Polyglot Auditing')
    html = html.replace('Focus on user experience to enhance customer satisfaction.', 'Recursively discover and trace dependencies across npm, PyPI, Go, Maven, and Cargo simultaneously.')

    html = html.replace('Data-driven decision making', 'Pre-Deployment CI/CD Pipeline Gates')
    html = html.replace('Leverage analytics to guide your business strategy.', 'Deterministic risk thresholds (P0-P3) to block compromised dependencies from production builds.')

    html = html.replace('Sustainable business practices', 'Zero-Day Dependency Confusion Shield')
    html = html.replace('Implement eco-friendly initiatives to attract conscious consumers.', 'Levenshtein distance checks preventing public registry substitution and internal scope hijacking.')

    html = html.replace('Effective team collaboration', 'Transitive Blast Radius Impact')
    html = html.replace('Encourage open communication to boost productivity.', 'Compute exact mathematical blast radius across entire upstream and downstream service graphs.')

    html = html.replace('Agile project management', 'Lifecycle Script Execution Audits')
    html = html.replace('Adopt flexibility to adapt to changing market demands.', 'Inspect npm preinstall/postinstall hooks for hidden remote execution or credential exfiltration.')

    html = html.replace('Customer-centric approaches', 'Gemini AI Exploit Reasoning')
    html = html.replace('Prioritize customer feedback to improve service offerings.', 'Synthesize real-world attacker exploit scenarios and produce 1-click unified Git diff patches.')

    # 10. Pricing section: link buttons to /dashboard
    html = html.replace('href="/pricing"', 'href="/dashboard"')

    # 11. Testimonials text
    html = html.replace(
        'Using this AI tool has transformed the way I approach my marketing campaigns. Efficiency has skyrocketed!',
        'ChainSentry identified a critical prototype pollution in our transitive dependency tree and generated a clean git diff patch in seconds!'
    )
    html = html.replace(
        "The best investment I've made for my business. The AI generates content that truly resonates with my audience.",
        'The dependency reasoning and blast radius analysis gave our security team clear visibility into which CVEs were actually dangerous.'
    )

    # 12. FAQ Section: supply chain questions
    html = html.replace('What is Writemate AI?', 'What is ChainSentry?')
    html = html.replace('How does the AI writing assistant work?', 'How does ChainSentry calculate the Blast Radius?')
    html = html.replace('Can I try Writemate AI for free?', 'How does ChainSentry ensure Zero Code Execution?')
    html = html.replace('What types of content can I create?', 'Which package ecosystems are supported?')
    html = html.replace('Is my data secure?', 'What if Gemini API key is not configured?')

    # Add FAQ answers outside button properly inside the box
    html = html.replace(
        '</h3><span class="text-white/80 transition-transform "><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M5.75 9.625L12 15.875L18.25 9.625" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"></path></svg></span></button></div></div>',
        '</h3><span class="text-white/80 transition-transform duration-200 faq-arrow flex-shrink-0"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M5.75 9.625L12 15.875L18.25 9.625" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"></path></svg></span></button><div class="faq-ans text-zinc-300 text-sm mt-3 leading-relaxed hidden">ChainSentry AI is an automated, zero-code-execution Software Supply Chain Security Analyzer and Remediation Engine. It statically inspects polyglot source code and dependency manifests to identify direct and transitive CVE vulnerabilities, typosquatting indicators, build provenance flaws, and calculates mathematical blast radius across services, while generating 1-click AI remediation patches.</div></div></div>',
        1
    )

    # 13. Bottom CTA Section
    html = html.replace('Ready to write 10× faster?', 'Ready to secure your software supply chain?')
    html = html.replace(
        'Create a professional website in minutes — no coding, no hassle.',
        'Analyze your repositories, discover hidden blast radius threats, and generate 1-click Git patches in seconds.'
    )
    html = html.replace('Explore templates', 'API Documentation')
    html = html.replace('href="/tools"', 'href="/docs"')

    # 14. Footer branding
    html = html.replace('WriteMate', 'ChainSentry')
    html = html.replace('Writemate', 'ChainSentry')

    # Add interactive FAQ script inline
    faq_script = '''
    <script>
    function handleHeroSubmit(e) {
        if (e && e.preventDefault) e.preventDefault();
        const input = document.getElementById("hero-repo-url");
        if (!input) return false;
        const val = input.value.trim();
        if (!val) { input.focus(); return false; }
        window.location.href = "/dashboard?repo=" + encodeURIComponent(val);
        return false;
    }
    function fillAndSubmit(url) {
        const input = document.getElementById("hero-repo-url");
        if (input) input.value = url;
        window.location.href = "/dashboard?repo=" + encodeURIComponent(url);
    }
    document.addEventListener("DOMContentLoaded", () => {
        document.querySelectorAll(".faq-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                const ans = btn.parentElement.querySelector(".faq-ans");
                if (ans) ans.classList.toggle("hidden");
            });
        });
    });
    </script>
    '''
    html = html.replace('</body>', faq_script + '</body>')

    with open('frontend/landing.html', 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"Successfully generated frontend/landing.html ({len(html)} bytes)")

if __name__ == "__main__":
    main()
