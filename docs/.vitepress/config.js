import { withMermaid } from 'vitepress-plugin-mermaid';

// withMermaid renders ```mermaid fences client-side. Both packages are pinned to
// exact versions in package.json: a diagram library is a large dependency tree
// and should change only when someone means it to.
export default withMermaid({
  // Set to "/<repo>/" when publishing to GitHub Pages, as naso does with "/naso/".
  base: process.env.DOCS_BASE ?? '/',
  title: 'SecYourScan',
  titleTemplate: ':title - SecYourScan Docs',
  // The meta description: the line a search result shows under the title. Say
  // what it monitors, for whom, and the one property that distinguishes it.
  description:
    "Self-hosted exposure monitoring for your organisation's own domains, emails, keywords, IPs and wallets across breach, paste and dark-web material.",
  cleanUrls: true,
  appearance: 'dark',
  mermaid: {
    // Follow the site theme instead of mermaid's default light palette.
    theme: 'dark',
  },
  themeConfig: {
    nav: [
      { text: 'Overview', link: '/guide/' },
      { text: 'Deploy', link: '/guide/deployment' },
      { text: 'API Reference', link: '/api/' },
    ],
    // Same mechanism as naso's docs: VitePress local search. At build time each
    // page is split at its headings and every section becomes one MiniSearch
    // document; the index ships as a lazy-loaded JS chunk and is searched
    // entirely in the browser — no server, no third-party service.
    // The values below are the ones observed in naso's live bundle (they are
    // also VitePress's defaults), written out so they can be tuned.
    search: {
      provider: 'local',
      options: {
        miniSearch: {
          searchOptions: {
            fuzzy: 0.2,
            prefix: true,
            boost: { title: 4, text: 2, titles: 1 },
          },
        },
      },
    },
    sidebar: [
      {
        text: 'Platform',
        collapsed: false,
        items: [
          { text: 'Introduction', link: '/guide/' },
          { text: 'Architecture', link: '/guide/architecture' },
          { text: 'The Leak Pipeline', link: '/guide/pipeline' },
        ],
      },
      {
        text: 'Core Modules',
        collapsed: false,
        items: [
          { text: 'Watchlist & Alerting', link: '/guide/watchlist' },
          { text: 'Dark Web Recon', link: '/guide/dark-recon' },
          { text: 'External Risk', link: '/guide/external-risk' },
          { text: 'Customer Onboarding', link: '/guide/onboarding' },
          { text: 'Ingestion', link: '/guide/ingestion' },
          { text: 'Search', link: '/guide/search' },
          { text: 'AI Co-Analyst', link: '/guide/ai-coanalyst' },
          { text: 'MCP Server', link: '/guide/mcp-integration' },
          { text: 'SOAR & CTI', link: '/guide/soar-and-cti' },
          { text: 'Reporting & Audit', link: '/guide/reporting' },
        ],
      },
      {
        text: 'Running SecYourScan',
        collapsed: false,
        items: [
          { text: 'Configuration', link: '/guide/configuration' },
          { text: 'Deployment', link: '/guide/deployment' },
          { text: 'Security Model', link: '/guide/security' },
          { text: 'Operator Runbook', link: '/guide/runbook' },
        ],
      },
      {
        text: 'Reference',
        collapsed: false,
        items: [{ text: 'API', link: '/api/' }],
      },
    ],
    footer: {
      // Plain text: a raw <a href> here would not get `base` prepended.
      message: "For monitoring your own organisation's exposure only.",
    },
  },
});
