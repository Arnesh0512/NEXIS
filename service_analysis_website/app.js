/**
 * NEXIS Multi-Language Service Explorer
 * =====================================
 * Interactive client for inspecting 9 languages across 3 dedicated pages per language:
 *   Page 1: Modules Overview (filename at top with hover location, crypto modules green, non-crypto blue)
 *   Page 2: Files & Functions (file cards with exclusive sorting in page topbar, deep inspector modal)
 *   Page 3: Call Graph Tree (interactive D3 tree, nodes=functions, edges=caller->callee, green=crypto, blue=non-crypto)
 */

// Application State
const state = {
  data: null,
  activeLanguage: 'TypeScript',
  activePage: 'page2', // 'page1' | 'page2' | 'page3'
  activeFile: null,
  activeFunction: null,
  searchQuery: '',
  sortBy: 'depth_desc',
  cryptoOnly: false,
  page1Filters: {
    stdCrypto: true,
    stdNonCrypto: true,
    userCrypto: true,
    userNonCrypto: true
  },
  treeFilter: 'crypto_only',
  treeFileFilter: 'all',
  treeSelectedFile: 'all',
  treeSelectedFunction: 'all',
  treeFileSearchQuery: '',
  treeFuncSearchQuery: '',
  treeLayout: 'force',
  treeSearchQuery: '',
  selectedTreeNodeId: null,
  sidebarCollapsed: false
};

// Language Visual Metadata
const LANGUAGE_META = {
  'TypeScript': { icon: 'file-code', color: '#3178c6', ext: '.ts' },
  'Java':       { icon: 'coffee',    color: '#b07219', ext: '.java' },
  'Kotlin':     { icon: 'cpu',       color: '#a97bff', ext: '.kt' },
  'Rust':       { icon: 'settings',  color: '#dea584', ext: '.rs' },
  'JavaScript': { icon: 'code',      color: '#f1e05a', ext: '.js' },
  'C':          { icon: 'terminal',  color: '#555555', ext: '.c' },
  'Go':         { icon: 'zap',       color: '#00add8', ext: '.go' },
  'Python':     { icon: 'terminal',  color: '#3572a5', ext: '.py' },
  'C++':        { icon: 'shield',    color: '#f34b7d', ext: '.cpp' }
};

// Module Classification Fallback Regex & Exceptions
const CRYPTO_MODULE_RX = /(crypto|cipher|bcrypt|argon2|scrypt|jsonwebtoken|jwt|jose|openssl|liboqs|oqs|bouncycastle|tink|secp256k1|ed25519|dilithium|kyber|ml[-_]?kem|ml[-_]?dsa|sphincs|falcon|sha\d*|md5|hashlib|hmac|cryptography|pycryptodome|pycrypto|ring|rsa|aes|chacha20|poly1305|subtle|sodium|x509|tls|ssl|forge|jbcrypt|pkcs|signer|verifier)/i;
const FALSE_POSITIVES = new Set(['cstring', 'string.h', 'strings', 'assets', 'class', 'pass', 'fast', 'task']);

// DOM References
const elements = {
  // Sidebar & Global Stats
  sidebarAside: document.getElementById('sidebarAside'),
  btnToggleSidebar: document.getElementById('btnToggleSidebar'),
  btnSidebarCollapse: document.getElementById('btnSidebarCollapse'),
  languageNavList: document.getElementById('languageNavList'),
  statTotalFiles: document.getElementById('statTotalFiles'),

  // High-Level Website Topbar
  activeLangIcon: document.getElementById('activeLangIcon'),
  activeLangTitle: document.getElementById('activeLangTitle'),
  activeServiceBadge: document.getElementById('activeServiceBadge'),
  activeLangSubtitle: document.getElementById('activeLangSubtitle'),
  cryptoOnlyToggle: document.getElementById('cryptoOnlyToggle'),
  fileSearchInput: document.getElementById('fileSearchInput'),

  // Language Topbar (Dedicated per-language bar)
  languageTopBar: document.getElementById('languageTopBar'),
  navBtnPage1: document.getElementById('navBtnPage1'),
  navBtnPage2: document.getElementById('navBtnPage2'),
  navBtnPage3: document.getElementById('navBtnPage3'),
  langTopBarStats: document.getElementById('langTopBarStats'),

  // Page 1: Modules Overview
  page1View: document.getElementById('page1View'),
  page1CountBadge: document.getElementById('page1CountBadge'),
  page1CardsGrid: document.getElementById('page1CardsGrid'),
  page1CollectiveBadge: document.getElementById('page1CollectiveBadge'),
  page1CollectiveModulesContainer: document.getElementById('page1CollectiveModulesContainer'),
  filterBtnStdCrypto: document.getElementById('filterBtnStdCrypto'),
  filterBtnStdNonCrypto: document.getElementById('filterBtnStdNonCrypto'),
  filterBtnUserCrypto: document.getElementById('filterBtnUserCrypto'),
  filterBtnUserNonCrypto: document.getElementById('filterBtnUserNonCrypto'),

  // Page 2: Files & Functions
  page2View: document.getElementById('page2View'),
  cardCountBadge: document.getElementById('cardCountBadge'),
  fileSortSelect: document.getElementById('fileSortSelect'),
  fileCardsGrid: document.getElementById('fileCardsGrid'),

  // Page 3: 4-Section Call Graph Tree
  page3View: document.getElementById('page3View'),
  callTreeSvg: document.getElementById('callTreeSvg'),
  treeNodeTooltip: document.getElementById('treeNodeTooltip'),
  btnToggleLayout: document.getElementById('btnToggleLayout'),
  btnToggleLayoutText: document.getElementById('btnToggleLayoutText'),
  page3NodeEdgeBadge: document.getElementById('page3NodeEdgeBadge'),
  page3SelectionBadge: document.getElementById('page3SelectionBadge'),
  btnZoomIn: document.getElementById('btnZoomIn'),
  btnZoomOut: document.getElementById('btnZoomOut'),
  btnZoomFit: document.getElementById('btnZoomFit'),

  // Section 1: Files Sidebar
  page3FilesSection: document.getElementById('page3FilesSection'),
  page3FilesCountBadge: document.getElementById('page3FilesCountBadge'),
  page3FileSearch: document.getElementById('page3FileSearch'),
  page3FilesList: document.getElementById('page3FilesList'),

  // Section 4: Functions Sidebar
  page3FuncsSection: document.getElementById('page3FuncsSection'),
  page3FuncsCountBadge: document.getElementById('page3FuncsCountBadge'),
  page3FuncsFileScopeText: document.getElementById('page3FuncsFileScopeText'),
  page3FuncSearch: document.getElementById('page3FuncSearch'),
  page3FuncsList: document.getElementById('page3FuncsList'),

  // Modal Drawer Elements
  detailModalBackdrop: document.getElementById('detailModalBackdrop'),
  detailModalPanel: document.getElementById('detailModalPanel'),
  btnCloseModal: document.getElementById('btnCloseModal'),
  modalFileName: document.getElementById('modalFileName'),
  modalFilePath: document.getElementById('modalFilePath'),
  modalLangBadge: document.getElementById('modalLangBadge'),
  modalLOC: document.getElementById('modalLOC'),
  modalFuncCount: document.getElementById('modalFuncCount'),
  modalMaxDepth: document.getElementById('modalMaxDepth'),
  modalTotalImports: document.getElementById('modalTotalImports'),
  nonUserImportsCount: document.getElementById('nonUserImportsCount'),
  nonUserImportsList: document.getElementById('nonUserImportsList'),
  userImportsCount: document.getElementById('userImportsCount'),
  userImportsList: document.getElementById('userImportsList'),
  modalCryptoOnlyToggle: document.getElementById('modalCryptoOnlyToggle'),
  functionCountBadge: document.getElementById('functionCountBadge'),
  functionPillList: document.getElementById('functionPillList'),
  functionDetailPanel: document.getElementById('functionDetailPanel'),
  detailFunctionName: document.getElementById('detailFunctionName'),
  detailFunctionLines: document.getElementById('detailFunctionLines'),
  detailCryptoArtifactsList: document.getElementById('detailCryptoArtifactsList'),
  detailCallsTableBody: document.getElementById('detailCallsTableBody'),
  detailCallerSummaryBadge: document.getElementById('detailCallerSummaryBadge'),
  detailCallerDepthsContainer: document.getElementById('detailCallerDepthsContainer')
};

// Global D3 Tree state instances for Page 3
let treeZoomBehavior = null;
let treeCurrentNodes = [];
let treeCurrentLinks = [];
let currentBlastRadius = null;

// Helper: Categorize imported modules for a file into 4 distinct groups:
// 1. Standard Crypto (Green)
// 2. Standard Non-Crypto (Blue)
// 3. User Crypto (Yellow)
// 4. User Non-Crypto (Pink)
function getFileModuleCategories(fileObj) {
  if (fileObj.standard_crypto_modules && fileObj.standard_non_crypto_modules &&
      fileObj.user_crypto_modules && fileObj.user_non_crypto_modules) {
    return {
      stdCrypto: fileObj.standard_crypto_modules,
      stdNonCrypto: fileObj.standard_non_crypto_modules,
      userCrypto: fileObj.user_crypto_modules,
      userNonCrypto: fileObj.user_non_crypto_modules
    };
  }

  const nonUserMods = fileObj.modules_imported?.non_user_defined || [];
  const userMods = fileObj.modules_imported?.user_defined || [];

  function isCrypto(m) {
    const clean = m.trim().toLowerCase();
    if (FALSE_POSITIVES.has(clean)) return false;
    return CRYPTO_MODULE_RX.test(clean);
  }

  const stdCrypto = nonUserMods.filter(isCrypto);
  const stdNonCrypto = nonUserMods.filter(m => !isCrypto(m));
  const userCrypto = userMods.filter(isCrypto);
  const userNonCrypto = userMods.filter(m => !isCrypto(m));

  return {
    stdCrypto: Array.from(new Set(stdCrypto)),
    stdNonCrypto: Array.from(new Set(stdNonCrypto)),
    userCrypto: Array.from(new Set(userCrypto)),
    userNonCrypto: Array.from(new Set(userNonCrypto))
  };
}

// Helper: Get effective max call depth for a file depending on whether Crypto Only is active.
// When Crypto Only is ON, non-crypto functions are excluded, so max depth reflects ONLY visible crypto functions.
function getFileMaxDepth(fileObj, isCryptoOnly = state.cryptoOnly) {
  if (!fileObj) return 0;
  if (!isCryptoOnly) {
    return fileObj.max_depth || 0;
  }
  if (fileObj.crypto_max_depth !== undefined) {
    return fileObj.crypto_max_depth;
  }
  const cryptoFuncs = (fileObj.functions || []).filter(fn => fn.crypto_artifacts && fn.crypto_artifacts.length > 0);
  if (cryptoFuncs.length === 0) return 0;
  return Math.max(0, ...cryptoFuncs.map(fn => (fn.caller_hierarchy && fn.caller_hierarchy.max_depth) || 0));
}

// Initialize Application
async function init() {
  // 1. Load Data
  if (window.NEXIS_DATA) {
    state.data = window.NEXIS_DATA;
  } else {
    try {
      const resp = await fetch('data/services_analysis.json');
      state.data = await resp.json();
    } catch (err) {
      console.error('Failed to load analysis JSON:', err);
      alert('Unable to load analysis data. Please run via a local web server.');
      return;
    }
  }

  // 2. Set Overall Stats
  if (state.data && state.data.total_files) {
    elements.statTotalFiles.textContent = state.data.total_files;
  }

  // 3. Render Sidebar
  renderSidebar();

  // 4. Render Active Language
  selectLanguage('TypeScript');

  // 5. Initialize Page 1 Filter UI
  updatePage1FilterButtonsUI();

  // 6. Setup Event Listeners
  setupEventListeners();
}

// Render 9 Languages in Sidebar
function renderSidebar() {
  if (!state.data || !state.data.languages) return;

  const langNames = Object.keys(state.data.languages);
  elements.languageNavList.innerHTML = '';

  langNames.forEach(langKey => {
    const langObj = state.data.languages[langKey];
    const meta = LANGUAGE_META[langKey] || { icon: 'code', color: '#10b981', ext: '' };

    const btn = document.createElement('button');
    btn.className = `lang-nav-item w-full px-3 py-2.5 rounded-lg border border-transparent text-left flex items-center justify-between text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800/60 transition-colors ${
      langKey === state.activeLanguage ? 'active' : ''
    }`;
    btn.dataset.lang = langKey;

    btn.innerHTML = `
      <div class="flex items-center space-x-2.5 truncate">
        <span class="w-2.5 h-2.5 rounded-full shrink-0" style="background-color: ${meta.color}"></span>
        <div class="truncate">
          <span class="font-bold block truncate text-slate-200">${langKey}</span>
          <span class="text-[10px] text-slate-400 font-mono block truncate">${langObj.service}</span>
        </div>
      </div>
      <span class="lang-badge px-2 py-0.5 rounded text-[11px] font-mono shrink-0 bg-slate-800 text-slate-400 border border-slate-700/80">
        ${langObj.file_count}
      </span>
    `;

    btn.addEventListener('click', () => {
      selectLanguage(langKey);
    });

    elements.languageNavList.appendChild(btn);
  });
}

// Select Language
function selectLanguage(langKey) {
  state.activeLanguage = langKey;
  state.searchQuery = '';
  if (elements.fileSearchInput) elements.fileSearchInput.value = '';

  // Update active state in sidebar
  document.querySelectorAll('.lang-nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.lang === langKey);
  });

  const langObj = state.data.languages[langKey];
  if (!langObj) return;

  // Update High-Level Header
  elements.activeLangTitle.textContent = langKey;
  elements.activeServiceBadge.textContent = langObj.service;
  elements.activeLangSubtitle.textContent = `Showing ${langObj.file_count} files present in services/${langObj.service}`;

  // Compute metrics for language topbar
  let totalFuncs = 0;
  let totalStdCrypto = new Set();
  let totalUserCrypto = new Set();
  langObj.files.forEach(f => {
    totalFuncs += (f.number_of_functions || 0);
    const cats = getFileModuleCategories(f);
    cats.stdCrypto.forEach(m => totalStdCrypto.add(m));
    cats.userCrypto.forEach(m => totalUserCrypto.add(m));
  });

  if (elements.langTopBarStats) {
    elements.langTopBarStats.innerHTML = `
      <span class="text-slate-300 font-semibold">${langObj.file_count}</span> Files
      <span class="text-slate-600">&bull;</span>
      <span class="text-slate-300 font-semibold">${totalFuncs}</span> Funcs
      <span class="text-slate-600">&bull;</span>
      <span class="text-emerald-400 font-semibold">${totalStdCrypto.size}</span> Std Crypto
      <span class="text-slate-600">&bull;</span>
      <span class="text-amber-400 font-semibold">${totalUserCrypto.size}</span> User Crypto
    `;
  }

  // Reset Page 3 selections when language changes
  state.treeSelectedFile = 'all';
  state.treeSelectedFunction = 'all';
  state.treeFileSearchQuery = '';
  state.treeFuncSearchQuery = '';
  state.selectedTreeNodeId = null;
  if (elements.page3FileSearch) elements.page3FileSearch.value = '';
  if (elements.page3FuncSearch) elements.page3FuncSearch.value = '';

  // Render current active page
  renderCurrentPage();

  if (window.lucide) lucide.createIcons();
}

// Switch between Page 1, Page 2, and Page 3
function switchPage(pageId) {
  state.activePage = pageId;

  // Update Language Topbar Tab Buttons
  const tabs = [
    { el: elements.navBtnPage1, id: 'page1' },
    { el: elements.navBtnPage2, id: 'page2' },
    { el: elements.navBtnPage3, id: 'page3' }
  ];

  tabs.forEach(t => {
    if (!t.el) return;
    const isActive = t.id === pageId;
    t.el.classList.toggle('active', isActive);
    if (isActive) {
      t.el.className = 'lang-nav-tab active px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold flex items-center space-x-2 border border-emerald-500/40 bg-emerald-500/15 text-emerald-300 transition-colors shadow-sm';
    } else {
      t.el.className = 'lang-nav-tab px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium flex items-center space-x-2 border border-transparent text-slate-400 hover:text-white hover:bg-slate-800 transition-colors';
    }
  });

  // Toggle Page Containers
  if (elements.page1View) elements.page1View.classList.toggle('hidden', pageId !== 'page1');
  if (elements.page2View) elements.page2View.classList.toggle('hidden', pageId !== 'page2');
  if (elements.page3View) elements.page3View.classList.toggle('hidden', pageId !== 'page3');

  renderCurrentPage();

  if (window.lucide) lucide.createIcons();
}

// Render whichever page is currently active
function renderCurrentPage() {
  if (state.activePage === 'page1') {
    renderPage1();
  } else if (state.activePage === 'page3') {
    renderPage3View();
  } else {
    renderFileCards(); // Page 2
  }
}

// Render Page 3 (4 sections: Files list, Merged graph canvas, Functions list)
function renderPage3View() {
  renderPage3FilesList();
  renderPage3FuncsList();
  renderPage3Tree();
}

// =========================================================================
// PAGE 1: Modules Overview
// Cards showing filename at top (hover shows file location),
// and 4 distinct module categories toggled by 4 header buttons:
//   1. Crypto (Standard Crypto - Green)
//   2. Non-Crypto (Standard Non-Crypto - Blue)
//   3. User Crypto (User Defined Crypto - Yellow)
//   4. User Non-Crypto (User Defined Non-Crypto - Pink)
// (Nothing happens on clicking the card)
// =========================================================================

// Toggle Page 1 category filter button
function togglePage1Filter(categoryKey) {
  if (state.page1Filters.hasOwnProperty(categoryKey)) {
    state.page1Filters[categoryKey] = !state.page1Filters[categoryKey];
    updatePage1FilterButtonsUI();
    renderPage1();
  }
}

// Update visual appearance of Page 1 filter buttons (Active vs Inactive)
function updatePage1FilterButtonsUI() {
  const configs = [
    { key: 'stdCrypto', el: elements.filterBtnStdCrypto, activeClass: 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300', dotClass: 'bg-emerald-400 shadow-sm shadow-emerald-400/50' },
    { key: 'stdNonCrypto', el: elements.filterBtnStdNonCrypto, activeClass: 'bg-sky-500/15 border-sky-500/40 text-sky-300', dotClass: 'bg-sky-400 shadow-sm shadow-sky-400/50' },
    { key: 'userCrypto', el: elements.filterBtnUserCrypto, activeClass: 'bg-amber-500/15 border-amber-500/40 text-amber-300', dotClass: 'bg-amber-400 shadow-sm shadow-amber-400/50' },
    { key: 'userNonCrypto', el: elements.filterBtnUserNonCrypto, activeClass: 'bg-pink-500/15 border-pink-500/40 text-pink-300', dotClass: 'bg-pink-400 shadow-sm shadow-pink-400/50' }
  ];

  configs.forEach(cfg => {
    if (!cfg.el) return;
    const isOn = state.page1Filters[cfg.key];
    const dot = cfg.el.querySelector('.indicator-dot');

    if (isOn) {
      cfg.el.className = `cat-filter-btn px-3 py-1.5 rounded-lg text-xs font-mono font-semibold flex items-center space-x-1.5 border transition-all active ${cfg.activeClass}`;
      if (dot) dot.className = `w-2 h-2 rounded-full indicator-dot ${cfg.dotClass}`;
    } else {
      cfg.el.className = 'cat-filter-btn px-3 py-1.5 rounded-lg text-xs font-mono font-medium flex items-center space-x-1.5 border transition-all bg-slate-900/60 border-slate-800 text-slate-500 hover:text-slate-400 hover:border-slate-700 opacity-60';
      if (dot) dot.className = 'w-2 h-2 rounded-full indicator-dot bg-slate-600 shadow-none';
    }
  });
}

// Render Collective Modules Directory for Page 1 (1 part of 3:1 ratio)
// Shows unique modules across all files in the active language, colored by the 4 categories
function renderPage1CollectiveModules(langObj) {
  if (!elements.page1CollectiveModulesContainer) return;

  const query = state.searchQuery.toLowerCase().trim();

  // Aggregate modules and file counts across ALL files in the active language
  const collective = {
    stdCrypto: new Map(),
    stdNonCrypto: new Map(),
    userCrypto: new Map(),
    userNonCrypto: new Map()
  };

  langObj.files.forEach(f => {
    const cats = getFileModuleCategories(f);
    cats.stdCrypto.forEach(m => collective.stdCrypto.set(m, (collective.stdCrypto.get(m) || 0) + 1));
    cats.stdNonCrypto.forEach(m => collective.stdNonCrypto.set(m, (collective.stdNonCrypto.get(m) || 0) + 1));
    cats.userCrypto.forEach(m => collective.userCrypto.set(m, (collective.userCrypto.get(m) || 0) + 1));
    cats.userNonCrypto.forEach(m => collective.userNonCrypto.set(m, (collective.userNonCrypto.get(m) || 0) + 1));
  });

  const categoriesConfig = [
    {
      key: 'stdCrypto',
      title: 'Crypto',
      subtitle: 'Standard Crypto',
      color: 'emerald',
      dotClass: 'bg-emerald-400 shadow-sm shadow-emerald-400/50',
      badgeClass: 'bg-emerald-950/70 text-emerald-300 border-emerald-700/80 hover:border-emerald-500 hover:bg-emerald-900/60',
      countClass: 'bg-emerald-900/80 text-emerald-300',
      map: collective.stdCrypto
    },
    {
      key: 'stdNonCrypto',
      title: 'Non-Crypto',
      subtitle: 'Standard Non-Crypto',
      color: 'sky',
      dotClass: 'bg-sky-400 shadow-sm shadow-sky-400/50',
      badgeClass: 'bg-sky-950/70 text-sky-300 border-sky-700/80 hover:border-sky-500 hover:bg-sky-900/60',
      countClass: 'bg-sky-900/80 text-sky-300',
      map: collective.stdNonCrypto
    },
    {
      key: 'userCrypto',
      title: 'User Crypto',
      subtitle: 'User Defined Crypto',
      color: 'amber',
      dotClass: 'bg-amber-400 shadow-sm shadow-amber-400/50',
      badgeClass: 'bg-amber-950/70 text-amber-300 border-amber-700/80 hover:border-amber-500 hover:bg-amber-900/60',
      countClass: 'bg-amber-900/80 text-amber-300',
      map: collective.userCrypto
    },
    {
      key: 'userNonCrypto',
      title: 'User Non-Crypto',
      subtitle: 'User Defined Non-Crypto',
      color: 'pink',
      dotClass: 'bg-pink-400 shadow-sm shadow-pink-400/50',
      badgeClass: 'bg-pink-950/70 text-pink-300 border-pink-700/80 hover:border-pink-500 hover:bg-pink-900/60',
      countClass: 'bg-pink-900/80 text-pink-300',
      map: collective.userNonCrypto
    }
  ];

  let totalVisibleUniqueModules = 0;
  elements.page1CollectiveModulesContainer.innerHTML = '';

  categoriesConfig.forEach(cfg => {
    // Only display if this category is enabled in state.page1Filters
    if (!state.page1Filters[cfg.key]) return;

    // Filter modules by search query if any
    let modulesList = Array.from(cfg.map.entries())
      .filter(([name]) => !query || name.toLowerCase().includes(query))
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));

    if (modulesList.length === 0) return;

    totalVisibleUniqueModules += modulesList.length;

    const section = document.createElement('div');
    section.className = 'space-y-2';

    section.innerHTML = `
      <div class="flex items-center justify-between text-xs font-mono font-semibold pt-1 border-t border-slate-800/60 first:border-t-0 first:pt-0">
        <div class="flex items-center space-x-1.5">
          <span class="w-2 h-2 rounded-full ${cfg.dotClass}"></span>
          <span class="text-slate-200">${cfg.title}</span>
        </div>
        <span class="text-[10px] text-slate-400 bg-slate-800/80 px-1.5 py-0.5 rounded border border-slate-700/60">${modulesList.length}</span>
      </div>
      <div class="flex flex-wrap gap-1.5">
        ${modulesList.map(([name, count]) => `
          <button 
            type="button"
            class="collective-mod-pill px-2 py-1 rounded text-[11px] font-mono border transition-all text-left flex items-center space-x-1.5 cursor-pointer ${cfg.badgeClass}"
            data-module="${name}"
            title="Module: ${name} (imported in ${count} file${count === 1 ? '' : 's'}). Click to filter cards."
          >
            <span class="truncate max-w-[170px]">${name}</span>
            <span class="text-[9px] px-1 py-0.2 rounded font-bold ${cfg.countClass} shrink-0">${count}</span>
          </button>
        `).join('')}
      </div>
    `;

    // Click on any collective module button filters the cards
    section.querySelectorAll('.collective-mod-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        const modName = btn.dataset.module;
        if (elements.fileSearchInput) {
          elements.fileSearchInput.value = modName;
          state.searchQuery = modName;
          renderPage1();
        }
      });
    });

    elements.page1CollectiveModulesContainer.appendChild(section);
  });

  if (elements.page1CollectiveBadge) {
    elements.page1CollectiveBadge.textContent = `${totalVisibleUniqueModules}`;
  }

  if (totalVisibleUniqueModules === 0) {
    const totalActiveCategories = Object.values(state.page1Filters).filter(Boolean).length;
    elements.page1CollectiveModulesContainer.innerHTML = `
      <div class="py-8 text-center text-slate-500 font-mono text-xs italic">
        ${totalActiveCategories === 0 ? 'All module categories turned off by buttons.' : (query ? `No modules matched "${query}".` : 'No modules detected in this language.')}
      </div>
    `;
  }
}

function renderPage1() {
  const langObj = state.data.languages[state.activeLanguage];
  if (!langObj) return;

  // 1. Render Collective Modules (1 part of 3:1 ratio)
  renderPage1CollectiveModules(langObj);

  // 2. Render File Cards (3 parts of 3:1 ratio)
  const query = state.searchQuery.toLowerCase().trim();
  const filteredFiles = langObj.files.filter(f => {
    const cats = getFileModuleCategories(f);
    const matchesSearch = !query || 
      f.file_name.toLowerCase().includes(query) ||
      f.relative_path.toLowerCase().includes(query) ||
      (state.page1Filters.stdCrypto && cats.stdCrypto.some(m => m.toLowerCase().includes(query))) ||
      (state.page1Filters.stdNonCrypto && cats.stdNonCrypto.some(m => m.toLowerCase().includes(query))) ||
      (state.page1Filters.userCrypto && cats.userCrypto.some(m => m.toLowerCase().includes(query))) ||
      (state.page1Filters.userNonCrypto && cats.userNonCrypto.some(m => m.toLowerCase().includes(query)));

    return matchesSearch;
  });

  if (elements.page1CountBadge) {
    elements.page1CountBadge.textContent = `${filteredFiles.length} of ${langObj.files.length} files`;
  }
  elements.page1CardsGrid.innerHTML = '';

  if (filteredFiles.length === 0) {
    elements.page1CardsGrid.innerHTML = `
      <div class="col-span-full py-16 text-center text-slate-500 font-mono text-xs">
        No files matched "${query}"
      </div>
    `;
    return;
  }

  filteredFiles.forEach(fileObj => {
    const cats = getFileModuleCategories(fileObj);
    const card = document.createElement('div');
    card.className = 'module-card bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3.5 cursor-default select-none hover:border-slate-700 transition-colors';

    // Build badges for each enabled module category without section header lines
    const allBadgeList = [];

    // 1) Standard Crypto (Green)
    if (state.page1Filters.stdCrypto) {
      cats.stdCrypto.forEach(m => {
        allBadgeList.push(`
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/70 text-emerald-300 border border-emerald-700/80 flex items-center space-x-1" title="Crypto: ${m}">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            <span>${m}</span>
          </span>
        `);
      });
    }

    // 2) Non-Crypto (Blue)
    if (state.page1Filters.stdNonCrypto) {
      cats.stdNonCrypto.forEach(m => {
        allBadgeList.push(`
          <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-sky-950/70 text-sky-300 border border-sky-700/80 flex items-center space-x-1" title="Non-Crypto: ${m}">
            <span class="w-1.5 h-1.5 rounded-full bg-sky-400"></span>
            <span>${m}</span>
          </span>
        `);
      });
    }

    // 3) User Crypto (Yellow)
    if (state.page1Filters.userCrypto) {
      cats.userCrypto.forEach(m => {
        allBadgeList.push(`
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-950/70 text-amber-300 border border-amber-700/80 flex items-center space-x-1" title="User Crypto: ${m}">
            <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
            <span>${m}</span>
          </span>
        `);
      });
    }

    // 4) User Non-Crypto (Pink)
    if (state.page1Filters.userNonCrypto) {
      cats.userNonCrypto.forEach(m => {
        allBadgeList.push(`
          <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-pink-950/70 text-pink-300 border border-pink-700/80 flex items-center space-x-1" title="User Non-Crypto: ${m}">
            <span class="w-1.5 h-1.5 rounded-full bg-pink-400"></span>
            <span>${m}</span>
          </span>
        `);
      });
    }

    const totalCategoriesActive = Object.values(state.page1Filters).filter(Boolean).length;
    const emptyMessage = totalCategoriesActive === 0
      ? 'All module categories hidden'
      : (cats.stdCrypto.length + cats.stdNonCrypto.length + cats.userCrypto.length + cats.userNonCrypto.length === 0
        ? 'No imported modules'
        : 'No modules in enabled categories');

    const modulesContentHtml = allBadgeList.length > 0
      ? `<div class="flex flex-wrap gap-1.5 max-h-36 overflow-y-auto custom-scrollbar pt-1">${allBadgeList.join('')}</div>`
      : `<div class="pt-1"><span class="text-[11px] text-slate-500 font-mono italic">${emptyMessage}</span></div>`;

    card.innerHTML = `
      <!-- Card Top: Filename with Hover File Location Tooltip -->
      <div class="border-b border-slate-800/80 pb-3">
        <div class="relative group/name">
          <div class="flex items-start justify-between">
            <div class="w-7 h-7 rounded-md bg-slate-800 flex items-center justify-center text-slate-400 shrink-0 mr-2.5">
              <i data-lucide="file-text" class="w-3.5 h-3.5"></i>
            </div>
            <div class="flex-1 min-w-0">
              <h4 class="font-mono font-bold text-slate-100 text-xs tracking-tight break-all leading-snug cursor-help flex items-center space-x-1.5" title="${fileObj.relative_path}">
                <span class="hover:text-emerald-300 transition-colors">${fileObj.file_name}</span>
                <i data-lucide="info" class="w-3 h-3 text-slate-500 opacity-60 group-hover/name:opacity-100 group-hover/name:text-emerald-400 transition-opacity"></i>
              </h4>
              <!-- Hover Location Tooltip -->
              <div class="hidden group-hover/name:block absolute bottom-full left-0 mb-1.5 z-30 px-3 py-1.5 bg-slate-950/95 border border-slate-700 text-[11px] font-mono text-emerald-300 rounded-lg shadow-xl backdrop-blur-md pointer-events-none whitespace-normal max-w-sm">
                <div class="text-[9px] uppercase tracking-wider text-slate-400 mb-0.5">File Location</div>
                <div class="break-all font-semibold text-slate-200">${fileObj.relative_path}</div>
              </div>
              <span class="text-[10px] font-mono text-slate-500 block mt-0.5 truncate">${fileObj.service} &bull; ${fileObj.lines_of_code} LOC</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Modules Badges directly in 4 colors without header lines -->
      ${modulesContentHtml}
    `;

    // As requested: nothing happens on clicking the card
    elements.page1CardsGrid.appendChild(card);
  });

  if (window.lucide) lucide.createIcons();
}

// =========================================================================
// PAGE 2: Files & Functions (Current Interactive View)
// Displays file cards with sorting exclusive to this page topbar,
// clicking card opens full inspector drawer with function call depth.
// =========================================================================
function renderFileCards() {
  const langObj = state.data.languages[state.activeLanguage];
  if (!langObj) return;

  const query = state.searchQuery.toLowerCase().trim();
  const filteredFiles = langObj.files.filter(f => {
    const matchesSearch = !query || 
      f.file_name.toLowerCase().includes(query) || 
      f.relative_path.toLowerCase().includes(query);

    if (!matchesSearch) return false;

    if (state.cryptoOnly) {
      return (f.crypto_artifacts_count && f.crypto_artifacts_count > 0) ||
             (f.functions || []).some(fn => fn.crypto_artifacts && fn.crypto_artifacts.length > 0);
    }
    return true;
  });

  // Sort files according to state.sortBy (exclusive to Page 2)
  filteredFiles.sort((a, b) => {
    if (state.sortBy === 'depth_desc') {
      const da = getFileMaxDepth(a, state.cryptoOnly);
      const db = getFileMaxDepth(b, state.cryptoOnly);
      if (db !== da) return db - da;
      // Secondary parameter: Crypto artifacts count (descending)
      const ca = a.crypto_artifacts_count || 0;
      const cb = b.crypto_artifacts_count || 0;
      if (cb !== ca) return cb - ca;
      // Tertiary parameter: File name (alphabetical)
      return a.file_name.localeCompare(b.file_name);
    }
    if (state.sortBy === 'crypto_desc') {
      const ca = a.crypto_artifacts_count || 0;
      const cb = b.crypto_artifacts_count || 0;
      if (cb !== ca) return cb - ca;
      // Secondary parameter: Max call depth (descending)
      const da = getFileMaxDepth(a, state.cryptoOnly);
      const db = getFileMaxDepth(b, state.cryptoOnly);
      if (db !== da) return db - da;
      // Tertiary parameter: File name (alphabetical)
      return a.file_name.localeCompare(b.file_name);
    }
    if (state.sortBy === 'loc_desc') {
      return (b.lines_of_code || 0) - (a.lines_of_code || 0);
    }
    if (state.sortBy === 'funcs_desc') {
      const fa = state.cryptoOnly
        ? (a.crypto_functions_count !== undefined ? a.crypto_functions_count : (a.functions || []).filter(fn => fn.crypto_artifacts && fn.crypto_artifacts.length > 0).length)
        : (a.number_of_functions || 0);
      const fb = state.cryptoOnly
        ? (b.crypto_functions_count !== undefined ? b.crypto_functions_count : (b.functions || []).filter(fn => fn.crypto_artifacts && fn.crypto_artifacts.length > 0).length)
        : (b.number_of_functions || 0);
      return fb - fa;
    }
    return a.file_name.localeCompare(b.file_name);
  });

  if (elements.cardCountBadge) {
    elements.cardCountBadge.textContent = `${filteredFiles.length} of ${langObj.files.length}`;
  }
  elements.fileCardsGrid.innerHTML = '';

  if (filteredFiles.length === 0) {
    elements.fileCardsGrid.innerHTML = `
      <div class="col-span-full py-16 text-center text-slate-500 font-mono text-xs">
        No files matched "${query}" ${state.cryptoOnly ? '(with Crypto Only enabled)' : ''}
      </div>
    `;
    return;
  }

  filteredFiles.forEach(fileObj => {
    const card = document.createElement('div');
    card.className = 'file-card bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between cursor-pointer hover:border-emerald-500/50 hover:bg-slate-850';
    
    const effectiveDepth = getFileMaxDepth(fileObj, state.cryptoOnly);
    const cryptoFuncCount = fileObj.crypto_functions_count !== undefined
      ? fileObj.crypto_functions_count
      : (fileObj.functions || []).filter(fn => fn.crypto_artifacts && fn.crypto_artifacts.length > 0).length;

    const depthBadge = effectiveDepth > 0
      ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-teal-950/80 text-teal-300 border border-teal-800/80 flex items-center space-x-1" title="Max Call Depth: ${effectiveDepth} ${state.cryptoOnly ? '(Crypto functions only)' : '(All functions)'}">
          <i data-lucide="git-pull-request" class="w-3 h-3 text-teal-400"></i>
          <span>Depth ${effectiveDepth}</span>
        </span>`
      : `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-800/60 border border-slate-700/60 flex items-center space-x-1" title="Max Call Depth: 0">
          <i data-lucide="git-pull-request" class="w-3 h-3 text-slate-500"></i>
          <span>Depth 0</span>
        </span>`;

    const cryptoCount = fileObj.crypto_artifacts_count || 0;
    const cryptoBadge = cryptoCount > 0
      ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 flex items-center space-x-1" title="${(fileObj.unique_crypto_artifacts || []).join(', ')}">
          <i data-lucide="shield" class="w-3 h-3 text-emerald-400"></i>
          <span>${cryptoCount} Crypto</span>
        </span>`
      : `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold text-slate-400 bg-slate-800/60 border border-slate-700/60 flex items-center space-x-1" title="0 cryptographic artifacts detected">
          <i data-lucide="shield" class="w-3 h-3 text-slate-500"></i>
          <span>0 Crypto</span>
        </span>`;

    const funcsLabel = state.cryptoOnly
      ? `${cryptoFuncCount} / ${fileObj.number_of_functions} funcs`
      : `${fileObj.number_of_functions} funcs`;

    card.innerHTML = `
      <div>
        <div class="flex items-center justify-between mb-3">
          <div class="w-7 h-7 rounded-md bg-slate-800 flex items-center justify-center text-slate-400">
            <i data-lucide="file-text" class="w-3.5 h-3.5"></i>
          </div>
          <div class="flex items-center space-x-1.5 flex-wrap justify-end gap-y-1">
            ${depthBadge}
            ${cryptoBadge}
            <span class="text-[10px] font-mono text-slate-400 uppercase tracking-wider">${fileObj.lines_of_code} LOC</span>
          </div>
        </div>
        <h4 class="font-mono font-semibold text-slate-100 text-xs tracking-tight break-all leading-snug" title="${fileObj.file_name}">
          ${fileObj.file_name}
        </h4>
      </div>
      <div class="pt-3 mt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 font-mono">
        <span class="${state.cryptoOnly ? 'text-emerald-400 font-semibold' : ''}">${funcsLabel}</span>
        <span class="text-emerald-400 font-medium text-[10px] flex items-center space-x-1">
          <span>Inspect</span>
          <i data-lucide="chevron-right" class="w-3 h-3"></i>
        </span>
      </div>
    `;

    card.addEventListener('click', () => {
      openFileDetail(fileObj);
    });

    elements.fileCardsGrid.appendChild(card);
  });

  if (window.lucide) lucide.createIcons();
}

// Open File Detail Modal Drawer (Page 2)
function openFileDetail(fileObj, targetFunctionName = null) {
  state.activeFile = fileObj;

  elements.modalFileName.textContent = fileObj.file_name;
  elements.modalFilePath.textContent = fileObj.relative_path;
  elements.modalLangBadge.textContent = fileObj.language;
  elements.modalLOC.textContent = fileObj.lines_of_code;

  const cryptoFuncCount = fileObj.crypto_functions_count !== undefined
    ? fileObj.crypto_functions_count
    : (fileObj.functions || []).filter(fn => fn.crypto_artifacts && fn.crypto_artifacts.length > 0).length;
  const effectiveDepth = getFileMaxDepth(fileObj, state.cryptoOnly);

  if (elements.modalFuncCount) {
    elements.modalFuncCount.textContent = state.cryptoOnly
      ? `${cryptoFuncCount} / ${fileObj.number_of_functions}`
      : fileObj.number_of_functions;
  }

  if (elements.modalMaxDepth) {
    elements.modalMaxDepth.textContent = effectiveDepth;
  }

  const nonUserImports = fileObj.modules_imported?.non_user_defined || [];
  const userImports = fileObj.modules_imported?.user_defined || [];
  elements.modalTotalImports.textContent = nonUserImports.length + userImports.length;

  // Non-User Defined Imports
  elements.nonUserImportsCount.textContent = `${nonUserImports.length} modules`;
  elements.nonUserImportsList.innerHTML = '';
  if (nonUserImports.length === 0) {
    elements.nonUserImportsList.innerHTML = '<span class="text-xs text-slate-500 font-mono italic">None</span>';
  } else {
    nonUserImports.forEach(mod => {
      const tag = document.createElement('span');
      tag.className = 'px-2 py-0.5 rounded text-xs font-mono bg-emerald-950/40 text-emerald-300 border border-emerald-800/60';
      tag.textContent = mod;
      elements.nonUserImportsList.appendChild(tag);
    });
  }

  // User Defined Imports
  elements.userImportsCount.textContent = `${userImports.length} modules`;
  elements.userImportsList.innerHTML = '';
  if (userImports.length === 0) {
    elements.userImportsList.innerHTML = '<span class="text-xs text-slate-500 font-mono italic">None</span>';
  } else {
    userImports.forEach(mod => {
      const tag = document.createElement('span');
      tag.className = 'px-2 py-0.5 rounded text-xs font-mono bg-teal-950/40 text-teal-300 border border-teal-800/60';
      tag.textContent = mod;
      elements.userImportsList.appendChild(tag);
    });
  }

  // Render function pills (filtered if cryptoOnly is active)
  renderFunctionPills(fileObj, targetFunctionName);

  // Open Modal
  elements.detailModalBackdrop.classList.remove('hidden');
  setTimeout(() => {
    elements.detailModalBackdrop.classList.add('open');
  }, 10);

  if (window.lucide) lucide.createIcons();
}

// Synchronize and update crypto-only toggle state across high-level header & modal
function setCryptoOnly(enabled) {
  state.cryptoOnly = enabled;
  if (elements.cryptoOnlyToggle) elements.cryptoOnlyToggle.checked = enabled;
  if (elements.modalCryptoOnlyToggle) elements.modalCryptoOnlyToggle.checked = enabled;

  // Re-render current page
  renderCurrentPage();

  // If a file modal is currently open, re-render its function pills and update depth/func metrics
  if (state.activeFile) {
    const cryptoFuncCount = state.activeFile.crypto_functions_count !== undefined
      ? state.activeFile.crypto_functions_count
      : (state.activeFile.functions || []).filter(fn => fn.crypto_artifacts && fn.crypto_artifacts.length > 0).length;
    const effectiveDepth = getFileMaxDepth(state.activeFile, enabled);

    if (elements.modalFuncCount) {
      elements.modalFuncCount.textContent = enabled
        ? `${cryptoFuncCount} / ${state.activeFile.number_of_functions}`
        : state.activeFile.number_of_functions;
    }

    if (elements.modalMaxDepth) {
      elements.modalMaxDepth.textContent = effectiveDepth;
    }

    renderFunctionPills(state.activeFile);
  }
}

// Render Function Names as selectable pills (Page 2 Modal)
function renderFunctionPills(fileObj, targetFunctionName = null) {
  elements.functionPillList.innerHTML = '';
  const allFuncs = fileObj.functions || [];
  const funcs = state.cryptoOnly
    ? allFuncs.filter(fn => fn.crypto_artifacts && fn.crypto_artifacts.length > 0)
    : allFuncs;

  if (elements.functionCountBadge) {
    elements.functionCountBadge.classList.remove('hidden');
    if (state.cryptoOnly) {
      elements.functionCountBadge.textContent = `${funcs.length} / ${allFuncs.length} Crypto`;
      elements.functionCountBadge.className = 'ml-2 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800/80';
    } else {
      elements.functionCountBadge.textContent = `${allFuncs.length} Function${allFuncs.length === 1 ? '' : 's'}`;
      elements.functionCountBadge.className = 'ml-2 px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700';
    }
  }

  if (funcs.length === 0) {
    if (state.cryptoOnly) {
      elements.functionPillList.innerHTML = `
        <div class="w-full p-3 bg-amber-950/20 border border-amber-800/40 rounded-lg text-amber-300/90 font-mono text-xs flex items-center space-x-2">
          <i data-lucide="shield-alert" class="w-4 h-4 text-amber-400 shrink-0"></i>
          <span>No functions with cryptographic artifacts in this file (${allFuncs.length} non-crypto function${allFuncs.length === 1 ? '' : 's'} hidden by toggle).</span>
        </div>
      `;
    } else {
      elements.functionPillList.innerHTML = '<span class="text-xs text-slate-500 font-mono italic">No functions declared in this file.</span>';
    }
    elements.functionDetailPanel.classList.add('hidden');
    if (window.lucide) lucide.createIcons();
    return;
  }

  elements.functionDetailPanel.classList.remove('hidden');

  const selectedIdx = targetFunctionName
    ? Math.max(0, funcs.findIndex(fn => fn.name === targetFunctionName))
    : 0;

  funcs.forEach((fn, idx) => {
    const btn = document.createElement('button');
    const hasCrypto = fn.crypto_artifacts && fn.crypto_artifacts.length > 0;
    btn.className = `func-pill px-2.5 py-1 rounded-md text-xs font-mono border border-slate-700 bg-slate-800/80 text-slate-300 hover:text-white hover:bg-slate-700 flex items-center space-x-1.5 transition-colors ${
      idx === selectedIdx ? 'active' : ''
    }`;

    if (hasCrypto) {
      btn.innerHTML = `<i data-lucide="shield" class="w-3 h-3 text-emerald-400 shrink-0"></i><span>${fn.name}</span>`;
    } else {
      btn.textContent = fn.name;
    }

    btn.addEventListener('click', () => {
      document.querySelectorAll('.func-pill').forEach(el => el.classList.remove('active'));
      btn.classList.add('active');
      inspectFunction(fn);
    });

    elements.functionPillList.appendChild(btn);
  });

  if (window.lucide) lucide.createIcons();

  // Inspect the selected function
  inspectFunction(funcs[selectedIdx]);
}

// Inspect single function in Page 2 Modal
// (Caller depth hierarchy remains 100% complete across all depths)
function inspectFunction(fn) {
  state.activeFunction = fn;

  elements.detailFunctionName.textContent = `${fn.name}()`;
  elements.detailFunctionLines.textContent = `Lines ${fn.start_line} - ${fn.end_line}`;

  // Crypto Artifacts used inside function
  elements.detailCryptoArtifactsList.innerHTML = '';
  const cryptoList = fn.crypto_artifacts || [];
  if (cryptoList.length === 0) {
    elements.detailCryptoArtifactsList.innerHTML = '<span class="text-xs text-slate-500 font-mono italic">No cryptographic artifacts detected</span>';
  } else {
    cryptoList.forEach(art => {
      const shield = document.createElement('span');
      shield.className = 'px-2 py-0.5 rounded text-xs font-mono font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 flex items-center space-x-1';
      shield.innerHTML = `<i data-lucide="shield" class="w-3 h-3 text-emerald-400"></i><span>${art}</span>`;
      elements.detailCryptoArtifactsList.appendChild(shield);
    });
  }

  // External / Internal function calls inside it
  elements.detailCallsTableBody.innerHTML = '';
  const calls = fn.calls || [];
  if (calls.length === 0) {
    elements.detailCallsTableBody.innerHTML = `
      <tr>
        <td colspan="3" class="py-3 text-center text-slate-500 italic text-xs">No external/internal function calls identified</td>
      </tr>
    `;
  } else {
    calls.forEach(c => {
      const row = document.createElement('tr');
      row.className = 'hover:bg-slate-800/40 transition-colors';

      const typeBadge = c.type === 'external' 
        ? '<span class="px-1.5 py-0.5 rounded text-[10px] bg-sky-950/60 text-sky-400 border border-sky-800/60">External</span>'
        : '<span class="px-1.5 py-0.5 rounded text-[10px] bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">Internal</span>';

      row.innerHTML = `
        <td class="py-2 px-2.5 font-bold text-slate-200">${c.function_name}</td>
        <td class="py-2 px-2.5">${typeBadge}</td>
        <td class="py-2 px-2.5 text-slate-400 text-xs">${c.module}</td>
      `;
      elements.detailCallsTableBody.appendChild(row);
    });
  }

  // Caller Depth Hierarchy (Depth 1, Depth 2, Depth 3, ...)
  elements.detailCallerDepthsContainer.innerHTML = '';
  const hier = fn.caller_hierarchy || { max_depth: 0, total_callers: 0, depths: [] };
  
  if (!hier.depths || hier.depths.length === 0) {
    elements.detailCallerSummaryBadge.textContent = '0 Direct Callers';
    elements.detailCallerDepthsContainer.innerHTML = `
      <div class="p-3 bg-slate-950/60 rounded-lg border border-slate-800 text-center text-xs text-slate-500 font-mono italic">
        0 functions calling this function (top-level entrypoint, controller, or uninvoked handler).
      </div>
    `;
  } else {
    elements.detailCallerSummaryBadge.textContent = `${hier.total_callers} Total Callers (Max Depth: ${hier.max_depth})`;

    hier.depths.forEach(d => {
      const depthCard = document.createElement('div');
      depthCard.className = 'p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2';

      let depthTitle = '';
      if (d.depth === 1) {
        depthTitle = `Depth 1 (Direct Callers)`;
      } else if (d.depth === 2) {
        depthTitle = `Depth 2 (Indirect Callers via Depth 1)`;
      } else {
        depthTitle = `Depth ${d.depth} (Indirect Callers via Depth ${d.depth - 1})`;
      }

      const dotColor = d.depth === 1 ? 'bg-emerald-400' : d.depth === 2 ? 'bg-teal-400' : 'bg-sky-400';

      depthCard.innerHTML = `
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-2">
            <span class="w-2 h-2 rounded-full ${dotColor}"></span>
            <span class="text-xs font-bold font-mono text-slate-200">${depthTitle}</span>
          </div>
          <span class="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-slate-200 border border-slate-700">
            ${d.caller_count} function${d.caller_count > 1 ? 's' : ''} calling
          </span>
        </div>
        <div class="flex flex-wrap gap-1.5 pt-1">
          ${d.callers.map(c => `
            <span class="px-2 py-1 rounded text-[11px] font-mono bg-slate-900 border border-slate-700/80 text-slate-300 flex items-center space-x-1.5 hover:border-emerald-500/50 transition-colors" title="${c.name} in ${c.file}">
              <span class="text-emerald-400 font-semibold">${c.name}</span>
              <span class="text-slate-500 text-[10px]">(${c.file})</span>
            </span>
          `).join('')}
        </div>
      `;
      elements.detailCallerDepthsContainer.appendChild(depthCard);
    });
  }

  if (window.lucide) lucide.createIcons();
}

// Close Modal
function closeModal() {
  elements.detailModalBackdrop.classList.remove('open');
  setTimeout(() => {
    elements.detailModalBackdrop.classList.add('hidden');
    state.activeFile = null;
    state.activeFunction = null;
  }, 250);
}

// =========================================================================
// PAGE 3: 4-Section Call Graph Tree Architecture
// -------------------------------------------------------------------------
// Section 1: File Names Sidebar with "All Files" top option
// Sections 2 & 3: Merged D3 Interactive Directed Call Graph Canvas
// Section 4: Functions in Selected File with "All Functions of File" top option
//
// Color Depth Shading:
// - Depth 0 (Base functions in selected file): Dark green (crypto), Dark blue (non-crypto)
// - Upstream Callers (functions calling them): Same green/blue in progressively lighter shades
// - Complete upstream transitive depth traced until roots (nothing calls them anymore)
// - Clicking a function in Section 4 isolates that single function's tree/graph
// =========================================================================

// Depth color palette: Darkest jewel tones for Depth 0, progressively lighter for higher depths
function getNodeDepthColor(isCrypto, depth) {
  const d = Math.max(0, depth || 0);
  if (isCrypto) {
    switch (d) {
      case 0:
        return {
          fill: '#064e3b', stroke: '#059669', text: '#ecfdf5', indicator: '#10b981',
          badgeBg: '#022c22', badgeText: '#6ee7b7'
        };
      case 1:
        return {
          fill: '#047857', stroke: '#10b981', text: '#ecfdf5', indicator: '#34d399',
          badgeBg: '#064e3b', badgeText: '#a7f3d0'
        };
      case 2:
        return {
          fill: '#059669', stroke: '#34d399', text: '#ffffff', indicator: '#6ee7b7',
          badgeBg: '#047857', badgeText: '#d1fae5'
        };
      case 3:
        return {
          fill: '#10b981', stroke: '#6ee7b7', text: '#022c22', indicator: '#064e3b',
          badgeBg: '#059669', badgeText: '#ffffff'
        };
      default: // 4+
        return {
          fill: '#34d399', stroke: '#a7f3d0', text: '#022c22', indicator: '#064e3b',
          badgeBg: '#059669', badgeText: '#ffffff'
        };
    }
  } else {
    // Non-Crypto: Midnight navy blue to light sky blue
    switch (d) {
      case 0:
        return {
          fill: '#082f49', stroke: '#0284c7', text: '#f0f9ff', indicator: '#0ea5e9',
          badgeBg: '#031a29', badgeText: '#7dd3fc'
        };
      case 1:
        return {
          fill: '#0369a1', stroke: '#38bdf8', text: '#f0f9ff', indicator: '#7dd3fc',
          badgeBg: '#082f49', badgeText: '#bae6fd'
        };
      case 2:
        return {
          fill: '#0284c7', stroke: '#60a5fa', text: '#ffffff', indicator: '#93c5fd',
          badgeBg: '#0369a1', badgeText: '#e0f2fe'
        };
      case 3:
        return {
          fill: '#38bdf8', stroke: '#93c5fd', text: '#082f49', indicator: '#0369a1',
          badgeBg: '#0284c7', badgeText: '#ffffff'
        };
      default: // 4+
        return {
          fill: '#7dd3fc', stroke: '#bae6fd', text: '#082f49', indicator: '#082f49',
          badgeBg: '#0284c7', badgeText: '#ffffff'
        };
    }
  }
}

// SECTION 1: Render Files List Sidebar
function renderPage3FilesList() {
  const langObj = state.data?.languages?.[state.activeLanguage];
  if (!langObj || !elements.page3FilesList) return;

  const files = langObj.files || [];
  if (elements.page3FilesCountBadge) {
    elements.page3FilesCountBadge.textContent = files.length;
  }

  const query = (state.treeFileSearchQuery || '').toLowerCase().trim();
  const displayFiles = query
    ? files.filter(f => f.file_name.toLowerCase().includes(query))
    : files;

  elements.page3FilesList.innerHTML = '';

  // Top Option: "All Files"
  const isAllActive = state.treeSelectedFile === 'all';
  const allItem = document.createElement('div');
  allItem.className = `page3-file-item p-2.5 rounded-lg border flex items-center justify-between text-xs font-mono ${
    isAllActive 
      ? 'active border-emerald-500/70 text-white' 
      : 'bg-slate-950/40 border-slate-800 text-slate-300'
  }`;
  allItem.innerHTML = `
    <div class="flex items-center space-x-2 truncate">
      <i data-lucide="layers" class="w-3.5 h-3.5 ${isAllActive ? 'text-emerald-400' : 'text-slate-400'} shrink-0"></i>
      <span class="page3-item-title truncate font-medium">All Files</span>
    </div>
    <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold ${isAllActive ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-slate-800 text-slate-400'} shrink-0">
      ${files.length}
    </span>
  `;
  allItem.addEventListener('click', () => {
    state.treeSelectedFile = 'all';
    state.treeSelectedFunction = 'all';
    state.selectedTreeNodeId = null;
    renderPage3FilesList();
    renderPage3FuncsList();
    renderPage3Tree();
  });
  elements.page3FilesList.appendChild(allItem);

  // Individual File Items
  displayFiles.forEach(f => {
    const isFileActive = state.treeSelectedFile === f.file_name;
    const cryptoCount = f.crypto_artifacts_count || 0;
    const funcCount = f.functions ? f.functions.length : (f.number_of_functions || 0);

    const item = document.createElement('div');
    item.className = `page3-file-item p-2 rounded-lg border flex flex-col gap-1 text-xs font-mono ${
      isFileActive 
        ? 'active border-emerald-500/70 text-white' 
        : 'bg-slate-950/40 border-slate-800 text-slate-300'
    }`;
    item.title = f.file_name;
    item.innerHTML = `
      <div class="flex items-center justify-between gap-1">
        <div class="flex items-center space-x-1.5 truncate">
          <i data-lucide="${cryptoCount > 0 ? 'shield-check' : 'file-code'}" class="w-3.5 h-3.5 ${cryptoCount > 0 ? 'text-emerald-400' : 'text-sky-400'} shrink-0"></i>
          <span class="page3-item-title truncate font-medium">${f.file_name}</span>
        </div>
        ${cryptoCount > 0 ? `<span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700/60 shrink-0">Crypto</span>` : ''}
      </div>
      <div class="flex items-center justify-between text-[10px] text-slate-400 pl-5">
        <span>${funcCount} funcs</span>
        <span class="text-slate-500 truncate max-w-[90px]">${f.relative_path.split('/').slice(-2, -1)[0] || ''}</span>
      </div>
    `;
    item.addEventListener('click', () => {
      state.treeSelectedFile = f.file_name;
      state.treeSelectedFunction = 'all';
      state.selectedTreeNodeId = null;
      renderPage3FilesList();
      renderPage3FuncsList();
      renderPage3Tree();
    });
    elements.page3FilesList.appendChild(item);
  });

  if (window.lucide) lucide.createIcons();
}

// SECTION 4: Render Functions List Sidebar
function renderPage3FuncsList() {
  const langObj = state.data?.languages?.[state.activeLanguage];
  if (!langObj || !elements.page3FuncsList) return;

  let candidateFunctions = [];
  if (state.treeSelectedFile === 'all') {
    langObj.files.forEach(f => {
      (f.functions || []).forEach(fn => {
        candidateFunctions.push({ ...fn, file_name: f.file_name });
      });
    });
    if (elements.page3FuncsFileScopeText) {
      elements.page3FuncsFileScopeText.textContent = `Scope: All Files (${candidateFunctions.length} funcs)`;
    }
  } else {
    const fileObj = langObj.files.find(f => f.file_name === state.treeSelectedFile);
    candidateFunctions = fileObj ? (fileObj.functions || []).map(fn => ({ ...fn, file_name: fileObj.file_name })) : [];
    if (elements.page3FuncsFileScopeText) {
      elements.page3FuncsFileScopeText.innerHTML = `File: <strong class="text-slate-200">${state.treeSelectedFile}</strong>`;
    }
  }

  if (elements.page3FuncsCountBadge) {
    elements.page3FuncsCountBadge.textContent = candidateFunctions.length;
  }

  const query = (state.treeFuncSearchQuery || '').toLowerCase().trim();
  const displayFuncs = query
    ? candidateFunctions.filter(fn => fn.name.toLowerCase().includes(query))
    : candidateFunctions;

  elements.page3FuncsList.innerHTML = '';

  // Top Option: "All Functions of File" (or "All Functions")
  const isAllFuncActive = state.treeSelectedFunction === 'all';
  const topOptionTitle = state.treeSelectedFile === 'all' ? 'All Functions in Service' : 'All Functions of File';
  const allFuncItem = document.createElement('div');
  allFuncItem.className = `page3-func-item p-2.5 rounded-lg border flex items-center justify-between text-xs font-mono ${
    isAllFuncActive 
      ? 'active border-sky-500/70 text-white' 
      : 'bg-slate-950/40 border-slate-800 text-slate-300'
  }`;
  allFuncItem.innerHTML = `
    <div class="flex items-center space-x-2 truncate">
      <i data-lucide="list-tree" class="w-3.5 h-3.5 ${isAllFuncActive ? 'text-sky-400' : 'text-slate-400'} shrink-0"></i>
      <span class="page3-item-title truncate font-medium">${topOptionTitle}</span>
    </div>
    <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold ${isAllFuncActive ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40' : 'bg-slate-800 text-slate-400'} shrink-0">
      ${candidateFunctions.length}
    </span>
  `;
  allFuncItem.addEventListener('click', () => {
    state.treeSelectedFunction = 'all';
    state.selectedTreeNodeId = null;
    renderPage3FuncsList();
    renderPage3Tree();
  });
  elements.page3FuncsList.appendChild(allFuncItem);

  // Individual Function Items
  displayFuncs.forEach(fn => {
    const isCrypto = Boolean(fn.crypto_artifacts && fn.crypto_artifacts.length > 0);
    const isFuncActive = state.treeSelectedFunction === fn.name;
    const callersList = (fn.caller_hierarchy && fn.caller_hierarchy.depths && fn.caller_hierarchy.depths[0])
      ? fn.caller_hierarchy.depths[0].callers : [];
    const callerCount = callersList.length;

    const item = document.createElement('div');
    item.className = `page3-func-item p-2 rounded-lg border flex flex-col gap-1 text-xs font-mono ${isCrypto ? 'is-crypto' : ''} ${
      isFuncActive 
        ? `active ${isCrypto ? 'border-emerald-500/70' : 'border-sky-500/70'} text-white` 
        : 'bg-slate-950/40 border-slate-800 text-slate-300'
    }`;
    item.title = `${fn.name}() - ${isCrypto ? 'Crypto' : 'Non-Crypto'} (${callerCount} callers)`;
    item.innerHTML = `
      <div class="flex items-center justify-between gap-1">
        <div class="flex items-center space-x-1.5 truncate">
          <span class="w-2 h-2 rounded-full ${isCrypto ? 'bg-emerald-400' : 'bg-sky-400'} shrink-0"></span>
          <span class="page3-item-title truncate font-medium">${fn.name}()</span>
        </div>
        <span class="px-1.5 py-0.2 rounded text-[9px] font-bold ${isCrypto ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/60' : 'bg-sky-950 text-sky-300 border border-sky-700/60'} shrink-0">
          ${isCrypto ? 'Crypto' : 'Normal'}
        </span>
      </div>
      <div class="flex items-center justify-between text-[10px] text-slate-400 pl-3.5">
        <span>Lines ${fn.start_line}-${fn.end_line}</span>
        <span class="text-slate-400 font-semibold">${callerCount} callers</span>
      </div>
      ${state.treeSelectedFile === 'all' && fn.file_name ? `<div class="text-[9px] text-slate-500 truncate pl-3.5">${fn.file_name}</div>` : ''}
    `;
    item.addEventListener('click', () => {
      state.treeSelectedFunction = fn.name;
      state.selectedTreeNodeId = null;
      renderPage3FuncsList();
      renderPage3Tree();
    });
    elements.page3FuncsList.appendChild(item);
  });

  if (window.lucide) lucide.createIcons();
}

// SECTIONS 2 & 3: Render Interactive Call Graph Canvas
function renderPage3Tree() {
  const langObj = state.data?.languages?.[state.activeLanguage];
  if (!langObj || !elements.callTreeSvg) return;

  // 1. Build complete graph model for the active language
  const nodeMap = new Map();
  const allNodes = [];

  langObj.files.forEach(f => {
    (f.functions || []).forEach(fn => {
      const nodeId = `${f.file_name}::${fn.name}`;
      const isCrypto = Boolean(fn.crypto_artifacts && fn.crypto_artifacts.length > 0);
      const callersList = (fn.caller_hierarchy && fn.caller_hierarchy.depths && fn.caller_hierarchy.depths[0])
        ? fn.caller_hierarchy.depths[0].callers
        : [];

      const nodeObj = {
        id: nodeId,
        name: fn.name,
        file_name: f.file_name,
        relative_path: f.relative_path,
        start_line: fn.start_line,
        end_line: fn.end_line,
        isCrypto: isCrypto,
        crypto_artifacts: fn.crypto_artifacts || [],
        callers: callersList,
        calls: fn.calls || [],
        inDegree: 0,
        outDegree: 0,
        depth: 0,
        isTarget: false
      };

      allNodes.push(nodeObj);
      nodeMap.set(nodeId, nodeObj);
      if (!nodeMap.has(fn.name)) nodeMap.set(fn.name, nodeObj);
    });
  });

  // Directed links: Caller -> Callee
  const allLinks = [];
  const linkKeySet = new Set();

  allNodes.forEach(calleeNode => {
    (calleeNode.callers || []).forEach(callerInfo => {
      const callerId = `${callerInfo.file}::${callerInfo.name}`;
      const callerNode = nodeMap.get(callerId) || (callerInfo.file ? allNodes.find(n => n.file_name === callerInfo.file && n.name === callerInfo.name) : null);

      if (callerNode && callerNode.id !== calleeNode.id) {
        const linkKey = `${callerNode.id}->${calleeNode.id}`;
        if (!linkKeySet.has(linkKey)) {
          linkKeySet.add(linkKey);
          allLinks.push({
            source: callerNode.id,
            target: calleeNode.id,
            sourceNode: callerNode,
            targetNode: calleeNode
          });
          callerNode.outDegree++;
          calleeNode.inDegree++;
        }
      }
    });
  });

  // 2. Base target functions & complete upstream transitive caller BFS
  let visibleNodes = [];
  let visibleLinks = [];

  const isSpecificFile = state.treeSelectedFile && state.treeSelectedFile !== 'all';
  const isSpecificFunc = state.treeSelectedFunction && state.treeSelectedFunction !== 'all';

  if (isSpecificFile || isSpecificFunc) {
    let baseNodes = [];
    if (isSpecificFile && isSpecificFunc) {
      baseNodes = allNodes.filter(n => n.file_name === state.treeSelectedFile && n.name === state.treeSelectedFunction);
    } else if (isSpecificFile && !isSpecificFunc) {
      baseNodes = allNodes.filter(n => n.file_name === state.treeSelectedFile);
    } else {
      baseNodes = allNodes.filter(n => n.name === state.treeSelectedFunction);
    }

    if (baseNodes.length === 0) {
      baseNodes = allNodes.filter(n => n.name === state.treeSelectedFunction);
    }

    // Upstream Transitive BFS: Depth 0 (target functions) -> Depth 1 (callers) -> Depth 2 (callers of callers)...
    // "complete depth until nothing gets called any more"
    const nodeDepthMap = new Map();
    const queue = [];

    baseNodes.forEach(b => {
      nodeDepthMap.set(b.id, 0);
      b.depth = 0;
      b.isTarget = true;
      queue.push({ id: b.id, depth: 0 });
    });

    while (queue.length > 0) {
      const { id, depth } = queue.shift();
      const curr = nodeMap.get(id);
      if (!curr) continue;

      (curr.callers || []).forEach(callerInfo => {
        const callerId = `${callerInfo.file}::${callerInfo.name}`;
        const callerNode = nodeMap.get(callerId) || (callerInfo.file ? allNodes.find(n => n.file_name === callerInfo.file && n.name === callerInfo.name) : null);

        if (callerNode && callerNode.id !== curr.id) {
          if (!nodeDepthMap.has(callerNode.id)) {
            const nextDepth = depth + 1;
            nodeDepthMap.set(callerNode.id, nextDepth);
            callerNode.depth = nextDepth;
            callerNode.isTarget = false;
            queue.push({ id: callerNode.id, depth: nextDepth });
          }
        }
      });
    }

    visibleNodes = Array.from(nodeDepthMap.keys()).map(id => nodeMap.get(id)).filter(Boolean);
    const visibleIdSet = new Set(visibleNodes.map(n => n.id));
    visibleLinks = allLinks.filter(l => visibleIdSet.has(l.source) && visibleIdSet.has(l.target));
  } else {
    // "All Files" + "All Functions": render connected service network
    allNodes.forEach(n => {
      n.isTarget = n.isCrypto;
      n.depth = n.isCrypto ? 0 : (n.inDegree === 0 ? 2 : 1);
    });
    visibleNodes = allNodes.filter(n => n.inDegree > 0 || n.outDegree > 0 || n.isCrypto);
    const visibleIdSet = new Set(visibleNodes.map(n => n.id));
    visibleLinks = allLinks.filter(l => visibleIdSet.has(l.source) && visibleIdSet.has(l.target));
  }

  // Recalculate degrees for visible nodes
  const activeNodeMap = new Map(visibleNodes.map(n => [n.id, n]));
  visibleNodes.forEach(n => {
    n.inDegree = 0;
    n.outDegree = 0;
  });
  visibleLinks.forEach(l => {
    const s = activeNodeMap.get(l.source);
    const t = activeNodeMap.get(l.target);
    if (s) s.outDegree++;
    if (t) t.inDegree++;
    l.sourceNode = s;
    l.targetNode = t;
  });

  // Calculate layer index for flow: Highest depth callers (roots) on left (layer 0) -> targets on right
  const maxTreeDepth = d3.max(visibleNodes, d => d.depth || 0) || 0;
  visibleNodes.forEach(n => {
    n.layer = maxTreeDepth - (n.depth || 0);
  });

  // Update metrics badge
  if (elements.page3NodeEdgeBadge) {
    elements.page3NodeEdgeBadge.textContent = `${visibleNodes.length} Nodes / ${visibleLinks.length} Directed Calls`;
  }

  // Clear SVG
  const svg = d3.select('#callTreeSvg');
  svg.selectAll('*').remove();

  if (visibleNodes.length === 0) {
    svg.append('text')
      .attr('x', '50%')
      .attr('y', '50%')
      .attr('text-anchor', 'middle')
      .attr('fill', '#64748b')
      .attr('font-family', 'monospace')
      .attr('font-size', '13px')
      .text('No matching functions or call paths found for current selection');
    return;
  }

  // Dimensions & Setup
  const container = document.getElementById('treeCanvasWrapper');
  const width = (container && container.clientWidth > 100) ? container.clientWidth : 1200;
  const height = (container && container.clientHeight > 100) ? container.clientHeight : 700;

  // 3. Compute Coordinates (Hierarchical DAG vs Organic Network)
  if (state.treeLayout === 'hierarchical') {
    const adj = new Map();
    visibleNodes.forEach(n => adj.set(n.id, new Set()));
    visibleLinks.forEach(l => {
      adj.get(l.source).add(l.target);
      adj.get(l.target).add(l.source);
    });

    const visited = new Set();
    const components = [];
    visibleNodes.forEach(n => {
      if (!visited.has(n.id)) {
        const comp = [];
        const q = [n.id];
        visited.add(n.id);
        while (q.length > 0) {
          const curId = q.shift();
          comp.push(activeNodeMap.get(curId));
          (adj.get(curId) || []).forEach(nbr => {
            if (!visited.has(nbr)) {
              visited.add(nbr);
              q.push(nbr);
            }
          });
        }
        components.push(comp);
      }
    });

    components.sort((a, b) => {
      const aTargets = a.filter(n => n.depth === 0).length;
      const bTargets = b.filter(n => n.depth === 0).length;
      if (bTargets !== aTargets) return bTargets - aTargets;
      return b.length - a.length;
    });

    // Balanced 2D Multi-Column Shelf Grid Packing: Width ~ Height
    const colSpacing = 320;
    const rowSpacing = 75;

    let totalCompRows = 0;
    components.forEach(compNodes => {
      const minLayer = d3.min(compNodes, d => d.layer) || 0;
      const compLayers = [];
      compNodes.forEach(n => {
        const l = Math.max(0, n.layer - minLayer);
        if (!compLayers[l]) compLayers[l] = [];
        compLayers[l].push(n);
      });
      let maxCompRows = 1;
      compLayers.forEach(ln => { if (ln) maxCompRows = Math.max(maxCompRows, ln.length); });
      compNodes._compLayers = compLayers;
      compNodes._maxCompRows = maxCompRows;
      totalCompRows += maxCompRows + 1;
    });

    // Target a balanced aspect ratio: columns wrap so total width matches height
    const idealRowsPerColumn = Math.max(7, Math.round(Math.sqrt(totalCompRows * 1.5)));
    const targetColumnHeight = Math.max(650, idealRowsPerColumn * rowSpacing);

    let shelfX = 100;
    let currentY = 50;
    let currentShelfWidth = 0;

    components.forEach(compNodes => {
      const compLayers = compNodes._compLayers;
      const maxCompRows = compNodes._maxCompRows;
      const compHeight = maxCompRows * rowSpacing + 70;
      const compWidth = Math.max(1, compLayers.length) * colSpacing;

      // Wrap to next horizontal shelf column if current column exceeds targetColumnHeight
      if (currentY + compHeight > targetColumnHeight && currentY > 50) {
        shelfX += currentShelfWidth + 120;
        currentY = 50;
        currentShelfWidth = compWidth;
      } else {
        currentShelfWidth = Math.max(currentShelfWidth, compWidth);
      }

      compLayers.forEach((layerNodes, lIdx) => {
        if (!layerNodes) return;
        layerNodes.forEach((n, rIdx) => {
          n.x = shelfX + lIdx * colSpacing;
          n.y = currentY + rIdx * rowSpacing;
        });
      });

      currentY += compHeight;
    });
  } else {
    // Organic Force Network Layout: Balanced 2D Canvas Span with Guaranteed Clearance
    const nodeCount = visibleNodes.length;
    const maxLayer = Math.max(1, d3.max(visibleNodes, d => d.layer) || 1);

    // Each layer needs AT LEAST 340px horizontal clearance so 180px pills never overlap
    const minLayerWidth = (maxLayer + 1) * 340;
    const balancedDim = Math.max(minLayerWidth, Math.sqrt(nodeCount) * 240);
    const xSpan = Math.max(minLayerWidth, balancedDim * 1.15);
    const ySpan = Math.max(700, Math.min(xSpan * 0.9, Math.sqrt(nodeCount) * 190));

    // Distribute nodes with strict layer flow from left (layer 0) to right (maxLayer)
    visibleNodes.forEach(n => {
      const layerCenter = (n.layer / maxLayer - 0.5) * xSpan;
      n.x = layerCenter + (Math.random() - 0.5) * 30;
      n.y = (Math.random() - 0.5) * (nodeCount > 15 ? ySpan * 0.6 : 140);
    });

    const simulation = d3.forceSimulation(visibleNodes)
      .force('link', d3.forceLink(visibleLinks).id(d => d.id).distance(240).strength(0.6))
      .force('charge', d3.forceManyBody().strength(-850).distanceMax(2200))
      // Pill clearance radius: ensures 180x34 pill boxes don't collide
      .force('collide', d3.forceCollide().radius(115).iterations(4))
      // Centering forces
      .force('x', d3.forceX(d => (d.layer / maxLayer - 0.5) * xSpan).strength(0.24))
      .force('y', d3.forceY(0).strength(0.06))
      .stop();

    for (let i = 0; i < 300; ++i) {
      simulation.tick();
    }

    // Gentle Y-compression ONLY for very large graphs (300+ nodes) if vertically elongated; NEVER compress X!
    const minX = d3.min(visibleNodes, d => d.x) || 0;
    const maxX = d3.max(visibleNodes, d => d.x) || 1000;
    const minY = d3.min(visibleNodes, d => d.y) || 0;
    const maxY = d3.max(visibleNodes, d => d.y) || 1000;
    const actualWidth = Math.max(10, maxX - minX);
    const actualHeight = Math.max(10, maxY - minY);

    if (nodeCount > 50 && actualHeight > actualWidth * 1.35) {
      const yCompress = Math.min(1.5, actualHeight / (actualWidth * 1.1));
      const midY = (minY + maxY) / 2;
      visibleNodes.forEach(n => {
        n.y = midY + (n.y - midY) / yCompress;
      });
    }

    // Guaranteed Pill Anti-Overlap Relaxation Pass (Pill box: 180x34)
    // Enforces |dx| >= 225px or |dy| >= 52px so pills never touch or overlap
    const minDx = 225; // 180px pill width + 45px clear arrow margin
    const minDy = 52;  // 34px pill height + 18px vertical margin

    for (let iter = 0; iter < 20; iter++) {
      let hadOverlap = false;
      for (let i = 0; i < visibleNodes.length; i++) {
        for (let j = i + 1; j < visibleNodes.length; j++) {
          const n1 = visibleNodes[i];
          const n2 = visibleNodes[j];
          const dx = n2.x - n1.x;
          const dy = n2.y - n1.y;
          const absDx = Math.abs(dx);
          const absDy = Math.abs(dy);

          if (absDx < minDx && absDy < minDy) {
            hadOverlap = true;
            const overlapX = minDx - absDx;
            const overlapY = minDy - absDy;

            if (n1.layer !== undefined && n2.layer !== undefined && n1.layer !== n2.layer) {
              // Different layers: separate along X to maintain layer flow
              const signX = (n2.layer > n1.layer) ? 1 : (n2.layer < n1.layer ? -1 : (dx >= 0 ? 1 : -1));
              const pushX = overlapX * 0.6;
              n1.x -= pushX * 0.5 * signX;
              n2.x += pushX * 0.5 * signX;
            } else {
              // Same layer: separate along Y
              const signY = dy >= 0 ? 1 : -1;
              const pushY = overlapY * 0.6;
              n1.y -= pushY * 0.5 * signY;
              n2.y += pushY * 0.5 * signY;
            }
          }
        }
      }
      if (!hadOverlap) break;
    }
  }

  // 4. SVG Definitions (Arrowheads)
  const defs = svg.append('defs');

  defs.append('marker')
    .attr('id', 'tree-arrow')
    .attr('viewBox', '0 0 10 10')
    .attr('refX', 10)
    .attr('refY', 5)
    .attr('markerWidth', 7)
    .attr('markerHeight', 7)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M 0 1.5 L 10 5 L 0 8.5 z')
    .attr('fill', '#94a3b8');

  defs.append('marker')
    .attr('id', 'tree-arrow-active')
    .attr('viewBox', '0 0 10 10')
    .attr('refX', 10)
    .attr('refY', 5)
    .attr('markerWidth', 8)
    .attr('markerHeight', 8)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M 0 1.5 L 10 5 L 0 8.5 z')
    .attr('fill', '#34d399');

  defs.append('marker')
    .attr('id', 'tree-arrow-upstream')
    .attr('viewBox', '0 0 10 10')
    .attr('refX', 10)
    .attr('refY', 5)
    .attr('markerWidth', 8)
    .attr('markerHeight', 8)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M 0 1.5 L 10 5 L 0 8.5 z')
    .attr('fill', '#38bdf8');

  defs.append('marker')
    .attr('id', 'tree-arrow-downstream')
    .attr('viewBox', '0 0 10 10')
    .attr('refX', 10)
    .attr('refY', 5)
    .attr('markerWidth', 8)
    .attr('markerHeight', 8)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M 0 1.5 L 10 5 L 0 8.5 z')
    .attr('fill', '#34d399');

  function computeLinkPath(src, tgt) {
    if (!src || !tgt) return '';
    const W = 90; // half pill width (180 / 2)
    const H = 17; // half pill height (34 / 2)

    const dx = tgt.x - src.x;
    const dy = tgt.y - src.y;

    if (dx >= 120) {
      const x1 = src.x + W;
      const y1 = src.y;
      const x2 = tgt.x - W;
      const y2 = tgt.y;
      const mx = (x1 + x2) / 2;
      return `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
    }

    const dist = Math.hypot(dx, dy);
    if (dist < 10) return '';

    const tScaleX = W / (Math.abs(dx) || 0.001);
    const tScaleY = H / (Math.abs(dy) || 0.001);
    const tScale = Math.min(tScaleX, tScaleY);
    const x2 = tgt.x - dx * tScale;
    const y2 = tgt.y - dy * tScale;

    const sScaleX = W / (Math.abs(dx) || 0.001);
    const sScaleY = H / (Math.abs(dy) || 0.001);
    const sScale = Math.min(sScaleX, sScaleY);
    const x1 = src.x + dx * sScale;
    const y1 = src.y + dy * sScale;

    return `M ${x1} ${y1} L ${x2} ${y2}`;
  }

  // 5. Main Zoomable Container Group
  const g = svg.append('g').attr('class', 'tree-main-group');

  treeZoomBehavior = d3.zoom()
    .scaleExtent([0.15, 3.5])
    .on('zoom', (event) => {
      g.attr('transform', event.transform);
    });

  svg.call(treeZoomBehavior);

  // 6. Draw Directed Edges
  const linkElements = g.append('g')
    .attr('class', 'tree-links')
    .selectAll('path')
    .data(visibleLinks)
    .enter()
    .append('path')
    .attr('class', 'tree-edge')
    .attr('d', d => {
      const src = d.sourceNode || activeNodeMap.get(d.source);
      const tgt = d.targetNode || activeNodeMap.get(d.target);
      return computeLinkPath(src, tgt);
    })
    .attr('fill', 'none')
    .attr('stroke', '#64748b')
    .attr('stroke-width', 2)
    .attr('stroke-opacity', 0.75)
    .attr('marker-end', 'url(#tree-arrow)');

  // 7. Draw Nodes with Dark-to-Light Depth Coloring
  const nodeElements = g.append('g')
    .attr('class', 'tree-nodes')
    .selectAll('g')
    .data(visibleNodes)
    .enter()
    .append('g')
    .attr('class', 'tree-node-group')
    .attr('transform', d => `translate(${d.x}, ${d.y})`)
    .style('cursor', 'pointer');

  // Node Pill Box
  nodeElements.append('rect')
    .attr('x', -90)
    .attr('y', -17)
    .attr('width', 180)
    .attr('height', 34)
    .attr('rx', 17)
    .attr('fill', d => getNodeDepthColor(d.isCrypto, d.depth).fill)
    .attr('stroke', d => getNodeDepthColor(d.isCrypto, d.depth).stroke)
    .attr('stroke-width', d => d.depth === 0 ? 2.8 : 1.8)
    .attr('filter', d => d.depth === 0 ? (d.isCrypto ? 'drop-shadow(0 0 8px rgba(16, 185, 129, 0.45))' : 'drop-shadow(0 0 8px rgba(56, 189, 248, 0.45))') : null)
    .attr('class', 'node-box transition-all');

  // Mini Indicator Circle
  nodeElements.append('circle')
    .attr('cx', -74)
    .attr('cy', 0)
    .attr('r', 4.5)
    .attr('fill', d => getNodeDepthColor(d.isCrypto, d.depth).indicator);

  // Function Name Text
  nodeElements.append('text')
    .attr('x', -62)
    .attr('y', 0)
    .attr('dominant-baseline', 'central')
    .attr('fill', d => getNodeDepthColor(d.isCrypto, d.depth).text)
    .attr('font-family', 'JetBrains Mono, monospace')
    .attr('font-size', '11px')
    .attr('font-weight', d => d.depth === 0 ? 'bold' : '600')
    .text(d => {
      const label = d.name;
      return label.length > 15 ? label.substring(0, 13) + '..' : label;
    });

  // Depth Badge Pill (D0, D1, D2...)
  const depthBadges = nodeElements.append('g')
    .attr('class', 'depth-badge-group')
    .attr('transform', 'translate(54, 0)');

  depthBadges.append('rect')
    .attr('x', -4)
    .attr('y', -8.5)
    .attr('width', 28)
    .attr('height', 17)
    .attr('rx', 4.5)
    .attr('fill', d => getNodeDepthColor(d.isCrypto, d.depth).badgeBg)
    .attr('stroke', d => getNodeDepthColor(d.isCrypto, d.depth).stroke)
    .attr('stroke-width', 0.8)
    .attr('opacity', 0.95);

  depthBadges.append('text')
    .attr('x', 10)
    .attr('y', 0)
    .attr('dominant-baseline', 'central')
    .attr('text-anchor', 'middle')
    .attr('fill', d => getNodeDepthColor(d.isCrypto, d.depth).badgeText)
    .attr('font-family', 'JetBrains Mono, monospace')
    .attr('font-size', '9px')
    .attr('font-weight', 'bold')
    .text(d => d.depth === 0 ? 'D0' : `D${d.depth}`);

  // Store global references
  treeCurrentNodes = visibleNodes;
  treeCurrentLinks = visibleLinks;

  // Node blast radius highlight function
  function highlightTreeNode(targetNodeId) {
    if (!targetNodeId) {
      currentBlastRadius = null;
      nodeElements
        .attr('opacity', 1)
        .select('.node-box')
        .attr('stroke', d => getNodeDepthColor(d.isCrypto, d.depth).stroke)
        .attr('stroke-width', d => d.depth === 0 ? 2.8 : 1.8)
        .attr('filter', d => d.depth === 0 ? (d.isCrypto ? 'drop-shadow(0 0 8px rgba(16, 185, 129, 0.45))' : 'drop-shadow(0 0 8px rgba(56, 189, 248, 0.45))') : null);

      linkElements
        .attr('stroke-opacity', 0.75)
        .attr('stroke', '#64748b')
        .attr('stroke-width', 2)
        .attr('marker-end', 'url(#tree-arrow)');

      if (elements.page3SelectionBadge) {
        elements.page3SelectionBadge.classList.add('hidden');
        elements.page3SelectionBadge.classList.remove('inline-flex');
      }
      return;
    }

    // Build Inbound (Callers) and Outbound (Callees) adjacency maps
    const inboundMap = new Map();  // calleeId -> [{ callerId, linkKey }]
    const outboundMap = new Map(); // callerId -> [{ calleeId, linkKey }]

    visibleLinks.forEach(l => {
      const srcId = l.sourceNode ? l.sourceNode.id : (typeof l.source === 'object' ? l.source.id : l.source);
      const tgtId = l.targetNode ? l.targetNode.id : (typeof l.target === 'object' ? l.target.id : l.target);
      const linkKey = `${srcId}->${tgtId}`;

      if (!inboundMap.has(tgtId)) inboundMap.set(tgtId, []);
      inboundMap.get(tgtId).push({ callerId: srcId, linkKey });

      if (!outboundMap.has(srcId)) outboundMap.set(srcId, []);
      outboundMap.get(srcId).push({ calleeId: tgtId, linkKey });
    });

    // 1. Transitive Upstream BFS (Inbound Blast Radius: who calls or reaches targetNodeId)
    const upstreamCallers = new Map(); // callerId -> distance
    const upstreamLinks = new Set();
    const upQueue = [{ id: targetNodeId, dist: 0 }];

    while (upQueue.length > 0) {
      const { id, dist } = upQueue.shift();
      const inList = inboundMap.get(id) || [];
      inList.forEach(({ callerId, linkKey }) => {
        upstreamLinks.add(linkKey);
        if (!upstreamCallers.has(callerId) && callerId !== targetNodeId) {
          upstreamCallers.set(callerId, dist + 1);
          upQueue.push({ id: callerId, dist: dist + 1 });
        }
      });
    }

    // 2. Transitive Downstream BFS (Outbound Blast Radius: what does targetNodeId invoke)
    const downstreamCallees = new Map(); // calleeId -> distance
    const downstreamLinks = new Set();
    const downQueue = [{ id: targetNodeId, dist: 0 }];

    while (downQueue.length > 0) {
      const { id, dist } = downQueue.shift();
      const outList = outboundMap.get(id) || [];
      outList.forEach(({ calleeId, linkKey }) => {
        downstreamLinks.add(linkKey);
        if (!downstreamCallees.has(calleeId) && calleeId !== targetNodeId) {
          downstreamCallees.set(calleeId, dist + 1);
          downQueue.push({ id: calleeId, dist: dist + 1 });
        }
      });
    }

    currentBlastRadius = {
      targetNodeId,
      upstreamCallers,
      downstreamCallees,
      upstreamLinks,
      downstreamLinks
    };

    // 3. Highlight Nodes across Blast Radius
    nodeElements.each(function (n) {
      const isTarget = n.id === targetNodeId;
      const isCaller = upstreamCallers.has(n.id);
      const isCallee = downstreamCallees.has(n.id);
      const inBlastRadius = isTarget || isCaller || isCallee;
      const el = d3.select(this);

      el.attr('opacity', inBlastRadius ? 1 : 0.08);

      const box = el.select('.node-box');
      if (isTarget) {
        box.attr('stroke', '#fbbf24')
          .attr('stroke-width', 3.8)
          .attr('filter', 'drop-shadow(0 0 14px rgba(251, 191, 36, 0.95))');
      } else if (isCaller && isCallee) {
        box.attr('stroke', '#c084fc')
          .attr('stroke-width', 3.2)
          .attr('filter', 'drop-shadow(0 0 10px rgba(192, 132, 252, 0.8))');
      } else if (isCaller) {
        const dist = upstreamCallers.get(n.id);
        const strokeColor = dist === 1 ? '#38bdf8' : '#7dd3fc';
        box.attr('stroke', strokeColor)
          .attr('stroke-width', dist === 1 ? 3.2 : 2.4)
          .attr('filter', dist === 1 
            ? 'drop-shadow(0 0 10px rgba(56, 189, 248, 0.85))' 
            : 'drop-shadow(0 0 6px rgba(125, 211, 252, 0.55))');
      } else if (isCallee) {
        const dist = downstreamCallees.get(n.id);
        const strokeColor = dist === 1 ? '#34d399' : '#6ee7b7';
        box.attr('stroke', strokeColor)
          .attr('stroke-width', dist === 1 ? 3.2 : 2.4)
          .attr('filter', dist === 1 
            ? 'drop-shadow(0 0 10px rgba(52, 211, 153, 0.85))' 
            : 'drop-shadow(0 0 6px rgba(110, 231, 183, 0.55))');
      } else {
        box.attr('stroke', getNodeDepthColor(n.isCrypto, n.depth).stroke)
          .attr('stroke-width', n.depth === 0 ? 2.8 : 1.8)
          .attr('filter', null);
      }
    });

    // 4. Highlight Links across Blast Radius
    linkElements.each(function (l) {
      const srcId = l.sourceNode ? l.sourceNode.id : (typeof l.source === 'object' ? l.source.id : l.source);
      const tgtId = l.targetNode ? l.targetNode.id : (typeof l.target === 'object' ? l.target.id : l.target);
      const linkKey = `${srcId}->${tgtId}`;
      const isUpstream = upstreamLinks.has(linkKey);
      const isDownstream = downstreamLinks.has(linkKey);
      const el = d3.select(this);

      if (isUpstream || isDownstream) {
        el.attr('stroke-opacity', 1)
          .attr('stroke', isUpstream ? '#38bdf8' : '#34d399')
          .attr('stroke-width', 3)
          .attr('marker-end', isUpstream ? 'url(#tree-arrow-upstream)' : 'url(#tree-arrow-downstream)');
      } else {
        el.attr('stroke-opacity', 0.03)
          .attr('stroke', '#334155')
          .attr('stroke-width', 1)
          .attr('marker-end', 'url(#tree-arrow)');
      }
    });

    // 5. Update Selection Badge with Blast Radius stats
    if (elements.page3SelectionBadge) {
      const targetNode = visibleNodes.find(n => n.id === targetNodeId);
      const nodeName = targetNode ? targetNode.name : targetNodeId;
      const totalBlastRadius = upstreamCallers.size + downstreamCallees.size;
      elements.page3SelectionBadge.innerHTML = `
        <span class="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
        <span>Blast Radius: <strong>${nodeName}()</strong> &bull; <span class="text-sky-300 font-semibold">${upstreamCallers.size} Upstream Caller${upstreamCallers.size === 1 ? '' : 's'}</span> &bull; <span class="text-emerald-300 font-semibold">${downstreamCallees.size} Downstream Callee${downstreamCallees.size === 1 ? '' : 's'}</span> (${totalBlastRadius} Total Impact)</span>
        <span class="ml-1.5 text-slate-400 hover:text-white font-bold cursor-pointer" title="Clear blast radius selection">&times;</span>
      `;
      elements.page3SelectionBadge.classList.remove('hidden');
      elements.page3SelectionBadge.classList.add('inline-flex');
    }
  }

  // Node Interactions
  const tooltip = elements.treeNodeTooltip;

  nodeElements.on('pointerdown mousedown', function (event) {
    event.stopPropagation();
  });

  nodeElements.on('click', function (event, d) {
    event.stopPropagation();
    if (state.selectedTreeNodeId === d.id) {
      state.selectedTreeNodeId = null;
      highlightTreeNode(null);
    } else {
      state.selectedTreeNodeId = d.id;
      highlightTreeNode(d.id);
    }
  });

  nodeElements.on('dblclick', function (event, d) {
    event.stopPropagation();
    const lObj = state.data.languages[state.activeLanguage];
    if (!lObj) return;
    const fileObj = lObj.files.find(f => f.file_name === d.file_name);
    if (fileObj) {
      openFileDetail(fileObj, d.name);
    }
  });

  svg.on('click', function (event) {
    if (event.target === svg.node() || event.target.tagName.toLowerCase() === 'svg') {
      if (state.selectedTreeNodeId) {
        state.selectedTreeNodeId = null;
        highlightTreeNode(null);
      }
    }
  });

  // Hover Tooltip
  nodeElements
    .on('mouseenter', function (event, d) {
      if (!state.selectedTreeNodeId) {
        d3.select(this).select('.node-box')
          .attr('stroke', '#38bdf8')
          .attr('stroke-width', 2.8)
          .attr('filter', 'drop-shadow(0 0 8px rgba(56, 189, 248, 0.5))');
      }

      if (tooltip) {
        const typeBadge = d.isCrypto
          ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-600">🛡️ Crypto</span>`
          : `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-sky-950 text-sky-300 border border-sky-600">⚡ Non-Crypto</span>`;

        const depthLabel = d.depth === 0
          ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-600">Depth 0 (Target in File)</span>`
          : `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">Depth ${d.depth} (${d.depth === 1 ? 'Direct Caller' : 'Transitive Caller'})</span>`;

        const artifactsInfo = (d.crypto_artifacts && d.crypto_artifacts.length > 0)
          ? `<div class="p-2 rounded bg-emerald-950/40 border border-emerald-800/60 text-[11px] text-emerald-300 font-mono">
              <span class="text-[9px] uppercase tracking-wider text-slate-400 block font-semibold">Artifacts</span>
              ${d.crypto_artifacts.join(', ')}
            </div>`
          : '';

        let blastContextBadge = '';
        if (state.selectedTreeNodeId && currentBlastRadius) {
          if (d.id === state.selectedTreeNodeId) {
            blastContextBadge = `
              <div class="px-2 py-1 rounded bg-amber-950/80 border border-amber-500/80 text-[10px] text-amber-300 font-mono font-bold flex items-center space-x-1.5">
                <span class="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
                <span>🎯 Blast Radius Focal Center</span>
              </div>
            `;
          } else if (currentBlastRadius.upstreamCallers && currentBlastRadius.upstreamCallers.has(d.id)) {
            const dist = currentBlastRadius.upstreamCallers.get(d.id);
            blastContextBadge = `
              <div class="px-2 py-1 rounded bg-sky-950/80 border border-sky-500/80 text-[10px] text-sky-300 font-mono font-semibold flex items-center justify-between">
                <span>💥 Upstream Caller (Impacted)</span>
                <span class="font-bold text-sky-200">Distance ${dist}</span>
              </div>
            `;
          } else if (currentBlastRadius.downstreamCallees && currentBlastRadius.downstreamCallees.has(d.id)) {
            const dist = currentBlastRadius.downstreamCallees.get(d.id);
            blastContextBadge = `
              <div class="px-2 py-1 rounded bg-emerald-950/80 border border-emerald-500/80 text-[10px] text-emerald-300 font-mono font-semibold flex items-center justify-between">
                <span>💥 Downstream Dependency</span>
                <span class="font-bold text-emerald-200">Distance ${dist}</span>
              </div>
            `;
          } else {
            blastContextBadge = `
              <div class="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-500 font-mono italic">
                Outside current blast radius
              </div>
            `;
          }
        }

        tooltip.innerHTML = `
          <div class="space-y-2 min-w-[270px]">
            <div class="flex items-center justify-between pb-1.5 border-b border-slate-800">
              <span class="text-xs font-bold text-white font-mono">${d.name}()</span>
              ${typeBadge}
            </div>
            <div class="flex items-center justify-between">
              ${depthLabel}
            </div>
            ${blastContextBadge}
            <div class="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800 space-y-1">
              <div class="flex items-center space-x-1.5 text-[10px] uppercase font-mono tracking-wider text-slate-400 font-semibold">
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                <span>File Location</span>
              </div>
              <div class="text-[11px] text-emerald-300 font-mono font-semibold break-all leading-snug">
                ${d.relative_path}
              </div>
              <div class="text-[10px] text-slate-400 font-mono">
                Lines ${d.start_line} &ndash; ${d.end_line}
              </div>
            </div>
            ${artifactsInfo}
            <div class="pt-1.5 border-t border-slate-800 text-[10px] text-slate-400 flex items-center justify-between font-mono">
              <span>Callers: <strong class="text-slate-200">${d.inDegree}</strong></span>
              <span>Calls: <strong class="text-slate-200">${d.outDegree}</strong></span>
            </div>
            <div class="pt-2 border-t border-slate-800 flex items-center justify-between text-[10px] font-mono">
              <span class="text-slate-500 italic">Click: focus &bull; DblClick: inspect</span>
              <button 
                type="button" 
                class="px-2 py-0.5 rounded bg-emerald-600/80 hover:bg-emerald-500 text-white font-semibold text-[10px] transition-colors pointer-events-auto cursor-pointer"
                onclick="openFileDetailForNode('${d.file_name}', '${d.name}')"
              >
                Inspect &rsaquo;
              </button>
            </div>
          </div>
        `;

        tooltip.classList.remove('hidden');
        tooltip.style.left = `${event.offsetX + 16}px`;
        tooltip.style.top = `${event.offsetY - 20}px`;
      }
    })
    .on('mousemove', function (event) {
      if (tooltip) {
        tooltip.style.left = `${event.offsetX + 16}px`;
        tooltip.style.top = `${event.offsetY - 20}px`;
      }
    })
    .on('mouseleave', function (event, d) {
      if (tooltip) {
        tooltip.classList.add('hidden');
      }
      if (!state.selectedTreeNodeId) {
        d3.select(this).select('.node-box')
          .attr('stroke', getNodeDepthColor(d.isCrypto, d.depth).stroke)
          .attr('stroke-width', d.depth === 0 ? 2.8 : 1.8)
          .attr('filter', d.depth === 0 ? (d.isCrypto ? 'drop-shadow(0 0 8px rgba(16, 185, 129, 0.45))' : 'drop-shadow(0 0 8px rgba(56, 189, 248, 0.45))') : null);
      }
    });

  if (state.selectedTreeNodeId && visibleNodes.some(n => n.id === state.selectedTreeNodeId)) {
    highlightTreeNode(state.selectedTreeNodeId);
  } else {
    state.selectedTreeNodeId = null;
    highlightTreeNode(null);
  }

  fitTreeToScreen(visibleNodes, width, height);
}

// Helper: Auto-fit graph nodes into viewport
function fitTreeToScreen(nodes, width, height) {
  if (!nodes || nodes.length === 0 || !treeZoomBehavior) return;

  const minX = d3.min(nodes, d => d.x - 90) || 0;
  const maxX = d3.max(nodes, d => d.x + 90) || 1000;
  const minY = d3.min(nodes, d => d.y - 16) || 0;
  const maxY = d3.max(nodes, d => d.y + 16) || 600;

  const graphWidth = maxX - minX + 80;
  const graphHeight = maxY - minY + 80;

  const safeWidth = Math.max(width || 1200, 800);
  const safeHeight = Math.max(height || 700, 500);

  const scale = Math.max(0.12, Math.min(safeWidth / graphWidth, safeHeight / graphHeight, 1.2) * 0.88);
  const tx = (safeWidth - graphWidth * scale) / 2 - minX * scale;
  const ty = (safeHeight - graphHeight * scale) / 2 - minY * scale;

  const svg = d3.select('#callTreeSvg');
  svg.transition().duration(400).call(
    treeZoomBehavior.transform,
    d3.zoomIdentity.translate(tx, ty).scale(scale)
  );
}

// Sidebar Hide/Show Toggle Function
function toggleSidebar(forceState) {
  if (!elements.sidebarAside) return;

  const willCollapse = (typeof forceState === 'boolean')
    ? forceState
    : !elements.sidebarAside.classList.contains('collapsed');

  if (willCollapse) {
    elements.sidebarAside.classList.add('collapsed');
    state.sidebarCollapsed = true;
    if (elements.btnToggleSidebar) {
      elements.btnToggleSidebar.title = 'Show Languages Sidebar';
      elements.btnToggleSidebar.innerHTML = `<i data-lucide="panel-left-open" class="w-4 h-4 text-emerald-400"></i>`;
    }
  } else {
    elements.sidebarAside.classList.remove('collapsed');
    state.sidebarCollapsed = false;
    if (elements.btnToggleSidebar) {
      elements.btnToggleSidebar.title = 'Hide Languages Sidebar';
      elements.btnToggleSidebar.innerHTML = `<i data-lucide="panel-left" class="w-4 h-4 text-emerald-400"></i>`;
    }
  }

  if (window.lucide) {
    lucide.createIcons();
  }

  // Trigger resize/fit for Page 3 if currently active
  if (state.activePage === 'page3') {
    setTimeout(() => {
      const container = document.getElementById('treeCanvasWrapper');
      const width = (container && container.clientWidth > 100) ? container.clientWidth : 1200;
      const height = (container && container.clientHeight > 100) ? container.clientHeight : 700;
      fitTreeToScreen(treeCurrentNodes, width, height);
    }, 320);
  }
}

// Setup Event Listeners
function setupEventListeners() {
  // Sidebar Hide/Show Toggle Buttons
  if (elements.btnToggleSidebar) {
    elements.btnToggleSidebar.addEventListener('click', () => toggleSidebar());
  }
  if (elements.btnSidebarCollapse) {
    elements.btnSidebarCollapse.addEventListener('click', () => toggleSidebar(true));
  }

  // Window resize handler for Page 3 call graph auto-fit
  window.addEventListener('resize', () => {
    if (state.activePage === 'page3' && treeCurrentNodes) {
      const container = document.getElementById('treeCanvasWrapper');
      const width = (container && container.clientWidth > 100) ? container.clientWidth : 1200;
      const height = (container && container.clientHeight > 100) ? container.clientHeight : 700;
      fitTreeToScreen(treeCurrentNodes, width, height);
    }
  });

  // Global search input (updates active page)
  elements.fileSearchInput.addEventListener('input', (e) => {
    state.searchQuery = e.target.value;
    renderCurrentPage();
  });

  // Language Topbar Page Switcher Buttons
  if (elements.navBtnPage1) {
    elements.navBtnPage1.addEventListener('click', () => switchPage('page1'));
  }
  if (elements.navBtnPage2) {
    elements.navBtnPage2.addEventListener('click', () => switchPage('page2'));
  }
  if (elements.navBtnPage3) {
    elements.navBtnPage3.addEventListener('click', () => switchPage('page3'));
  }

  // Page 1 Category Filter Buttons (Crypto, Non-Crypto, User Crypto, User Non-Crypto)
  const p1Buttons = [
    { el: elements.filterBtnStdCrypto, cat: 'stdCrypto' },
    { el: elements.filterBtnStdNonCrypto, cat: 'stdNonCrypto' },
    { el: elements.filterBtnUserCrypto, cat: 'userCrypto' },
    { el: elements.filterBtnUserNonCrypto, cat: 'userNonCrypto' }
  ];

  p1Buttons.forEach(btn => {
    if (btn.el) {
      btn.el.addEventListener('click', () => togglePage1Filter(btn.cat));
    }
  });

  // Page 2 Sort dropdown selection (exclusive to Page 2)
  if (elements.fileSortSelect) {
    elements.fileSortSelect.value = state.sortBy;
    elements.fileSortSelect.addEventListener('change', (e) => {
      state.sortBy = e.target.value;
      renderFileCards();
    });
  }

  // Crypto only toggle controls (high level header & modal synced)
  if (elements.cryptoOnlyToggle) {
    elements.cryptoOnlyToggle.checked = state.cryptoOnly;
    elements.cryptoOnlyToggle.addEventListener('change', (e) => {
      setCryptoOnly(e.target.checked);
    });
  }
  if (elements.modalCryptoOnlyToggle) {
    elements.modalCryptoOnlyToggle.checked = state.cryptoOnly;
    elements.modalCryptoOnlyToggle.addEventListener('change', (e) => {
      setCryptoOnly(e.target.checked);
    });
  }

  // Page 3 Section 1 File Search Filter
  if (elements.page3FileSearch) {
    elements.page3FileSearch.addEventListener('input', (e) => {
      state.treeFileSearchQuery = e.target.value.toLowerCase().trim();
      renderPage3FilesList();
    });
  }

  // Page 3 Section 4 Function Search Filter
  if (elements.page3FuncSearch) {
    elements.page3FuncSearch.addEventListener('input', (e) => {
      state.treeFuncSearchQuery = e.target.value.toLowerCase().trim();
      renderPage3FuncsList();
    });
  }

  // Page 3 Layout Mode Toggle (Organic Network <-> Hierarchical DAG)
  if (elements.btnToggleLayout) {
    elements.btnToggleLayout.addEventListener('click', () => {
      state.treeLayout = state.treeLayout === 'force' ? 'hierarchical' : 'force';
      state.selectedTreeNodeId = null;
      if (elements.btnToggleLayoutText) {
        elements.btnToggleLayoutText.textContent = state.treeLayout === 'force' ? 'Organic Network' : 'Hierarchical DAG';
      }
      renderPage3Tree();
    });
  }

  // Page 3 Selection Reset Badge
  if (elements.page3SelectionBadge) {
    elements.page3SelectionBadge.addEventListener('click', () => {
      state.selectedTreeNodeId = null;
      renderPage3Tree();
    });
  }

  // Page 3 Zoom Buttons
  if (elements.btnZoomIn) {
    elements.btnZoomIn.addEventListener('click', () => {
      d3.select('#callTreeSvg').transition().duration(250).call(treeZoomBehavior.scaleBy, 1.3);
    });
  }
  if (elements.btnZoomOut) {
    elements.btnZoomOut.addEventListener('click', () => {
      d3.select('#callTreeSvg').transition().duration(250).call(treeZoomBehavior.scaleBy, 0.7);
    });
  }
  if (elements.btnZoomFit) {
    elements.btnZoomFit.addEventListener('click', () => {
      renderPage3Tree();
    });
  }

  // Close modal button
  elements.btnCloseModal.addEventListener('click', closeModal);

  // Close modal on clicking backdrop
  elements.detailModalBackdrop.addEventListener('click', (e) => {
    if (e.target === elements.detailModalBackdrop) {
      closeModal();
    }
  });

  // Escape key to close modal
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && elements.detailModalBackdrop.classList.contains('open')) {
      closeModal();
    }
  });
}

// Global helper for opening modal drawer from Page 3 hover tooltip
window.openFileDetailForNode = function (fileName, funcName) {
  const langObj = state.data.languages[state.activeLanguage];
  if (!langObj) return;
  const fileObj = langObj.files.find(f => f.file_name === fileName);
  if (fileObj) {
    openFileDetail(fileObj, funcName);
  }
};

// Boot
window.addEventListener('DOMContentLoaded', init);
