(() => {
  "use strict";

  const app = document.getElementById("app");
  const CONFIG_URL = "data/config.enc.json";
  const DB_NAME = "cps-dashboard-secure";
  const DB_STORE = "vault";
  const KEY_RECORD = "access-key";
  const CACHE_RECORD = "encrypted-data-cache";
  const REMEMBER_MS = 30 * 24 * 60 * 60 * 1000;
  const REFRESH_MS = 5 * 60 * 1000;

  const periodOptions = [
    ["today", "今日"],
    ["yesterday", "昨日"],
    ["7d", "近 7 天"],
    ["30d", "近 30 天"],
    ["month", "本月"],
    ["lastMonth", "上月"],
    ["all", "累计"],
  ];
  const metricOptions = [
    ["orders", "单"],
    ["commission", "佣金"],
    ["gmv", "成交"],
  ];

  const state = {
    bundle: null,
    config: null,
    key: null,
    data: null,
    loading: false,
    error: "",
    usingCache: false,
    channel: "全部",
    period: "30d",
    trendMetric: "orders",
    peakSegment: "weekday",
    view: "overview",
    dailyRange: 14,
    dailyChannel: "小红书",
    dailySearch: "",
    dailySort: "orders",
    dailyLayout: "matrix",
    expandedDates: new Set(),
    dailyExpansionReady: false,
    search: "",
    timer: null,
  };

  function bytesFromBase64(value) {
    return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  }

  function base64FromBytes(value) {
    let binary = "";
    for (const byte of value) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  function openVault() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(DB_STORE)) {
          request.result.createObjectStore(DB_STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function vaultGet(key) {
    const database = await openVault();
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(DB_STORE, "readonly");
      const request = transaction.objectStore(DB_STORE).get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      transaction.oncomplete = () => database.close();
    });
  }

  async function vaultSet(key, value) {
    const database = await openVault();
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(DB_STORE, "readwrite");
      transaction.objectStore(DB_STORE).put(value, key);
      transaction.oncomplete = () => {
        database.close();
        resolve();
      };
      transaction.onerror = () => reject(transaction.error);
    });
  }

  async function vaultDelete(key) {
    const database = await openVault();
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(DB_STORE, "readwrite");
      transaction.objectStore(DB_STORE).delete(key);
      transaction.oncomplete = () => {
        database.close();
        resolve();
      };
      transaction.onerror = () => reject(transaction.error);
    });
  }

  async function loadBundle() {
    const response = await fetch(`${CONFIG_URL}?v=${Date.now()}`, { cache: "no-store" });
    if (!response.ok) throw new Error("安全配置暂时无法读取");
    const bundle = await response.json();
    if (!bundle?.salt || !bundle?.iv || !bundle?.ciphertext) {
      throw new Error("安全配置格式异常");
    }
    return bundle;
  }

  async function deriveKey(password, bundle) {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: bytesFromBase64(bundle.salt),
        iterations: bundle.iterations || 250000,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  async function decryptBundle(bundle, key) {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytesFromBase64(bundle.iv) },
      key,
      bytesFromBase64(bundle.ciphertext),
    );
    const config = JSON.parse(new TextDecoder().decode(plaintext));
    if (config?.version !== 1 || !Array.isArray(config?.sources)) {
      throw new Error("配置验证失败");
    }
    return config;
  }

  async function saveAccessKey(key, bundle) {
    try {
      await vaultSet(KEY_RECORD, {
        key,
        salt: bundle.salt,
        expiresAt: Date.now() + REMEMBER_MS,
      });
    } catch {
      // Some private browsing modes disallow persistent IndexedDB.
    }
  }

  async function restoreAccessKey(bundle) {
    try {
      const saved = await vaultGet(KEY_RECORD);
      if (!saved?.key || saved.salt !== bundle.salt || saved.expiresAt <= Date.now()) {
        if (saved) await vaultDelete(KEY_RECORD);
        return null;
      }
      return saved.key;
    } catch {
      return null;
    }
  }

  async function saveEncryptedCache(data) {
    if (!state.key) return;
    try {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        state.key,
        new TextEncoder().encode(JSON.stringify(data)),
      );
      await vaultSet(CACHE_RECORD, {
        iv: base64FromBytes(iv),
        ciphertext: base64FromBytes(new Uint8Array(encrypted)),
        savedAt: Date.now(),
      });
    } catch {
      // The live dashboard remains available even if offline cache is unavailable.
    }
  }

  async function loadEncryptedCache() {
    if (!state.key) return null;
    try {
      const cached = await vaultGet(CACHE_RECORD);
      if (!cached?.iv || !cached?.ciphertext) return null;
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bytesFromBase64(cached.iv) },
        state.key,
        bytesFromBase64(cached.ciphertext),
      );
      return JSON.parse(new TextDecoder().decode(plaintext));
    } catch {
      return null;
    }
  }

  function setLoginStatus(message, isError = false) {
    const error = document.getElementById("loginError");
    const field = document.getElementById("passwordField");
    if (!error || !field) return;
    error.textContent = message;
    error.classList.toggle("hidden", !message);
    field.classList.toggle("has-error", isError);
  }

  function setLoginBusy(busy) {
    const button = document.getElementById("loginButton");
    const input = document.getElementById("dashboard-password");
    if (!button || !input) return;
    button.disabled = busy;
    input.disabled = busy;
    const label = button.querySelector(".button-label");
    if (label) label.textContent = busy ? "验证中…" : "进入数据看板";
  }

  async function unlockWithPassword(password) {
    setLoginBusy(true);
    setLoginStatus("正在验证密码，请稍候…");
    try {
      const key = await deriveKey(password, state.bundle);
      const config = await decryptBundle(state.bundle, key);
      state.key = key;
      state.config = config;
      await saveAccessKey(key, state.bundle);
      showDashboard();
    } catch {
      setLoginStatus("密码不正确，请重新输入", true);
      const input = document.getElementById("dashboard-password");
      input?.focus();
      input?.select();
    } finally {
      setLoginBusy(false);
    }
  }

  function dashboardTemplate() {
    return `
      <main class="dashboard-shell">
        <header class="topbar">
          <div class="brand-lockup">
            <div class="brand-mark" aria-hidden="true"><span></span>CPS</div>
            <div>
              <p class="eyebrow">渠道经营实时监测</p>
              <h1>CPS 数据驾驶舱</h1>
            </div>
          </div>
          <div class="sync-panel">
            <div class="sync-copy">
              <span class="live-dot" id="liveDot"></span>
              <div>
                <strong id="syncTitle">数据连接中</strong>
                <small id="syncTime">正在读取最新数据</small>
              </div>
            </div>
            <button class="refresh-button" id="refreshButton">
              <span id="refreshIcon">↻</span><span id="refreshLabel">立即刷新</span>
            </button>
          </div>
        </header>

        <nav class="view-switch" aria-label="看板界面切换">
          <button data-view="overview" class="active">
            <span>总</span><div><strong>经营看板</strong><small>趋势、预测与排名</small></div>
          </button>
          <button data-view="daily">
            <span>日</span><div><strong>每日明细</strong><small>逐日查看推广位变化</small></div>
          </button>
        </nav>

        <div class="dashboard-view" id="overviewView">

        <section class="toolbar" aria-label="数据筛选">
          <div class="segmented channel-tabs">
            ${["全部", "小红书", "企业微信"].map((value) => `
              <button data-channel="${value}" class="${value === "全部" ? "active" : ""}">
                ${value}${value === "全部" ? "" : `<span class="channel-mini-dot ${value === "小红书" ? "xhs" : "wecom"}"></span>`}
              </button>
            `).join("")}
          </div>
          <div class="segmented period-tabs">
            ${periodOptions.map(([value, label]) => `
              <button data-period="${value}" class="${value === "30d" ? "active" : ""}">${label}</button>
            `).join("")}
          </div>
        </section>

        <div class="error-banner hidden" id="errorBanner"></div>
        <section class="kpi-grid" id="kpiGrid" aria-label="核心指标"></section>

        <section class="main-grid">
          <article class="panel trend-panel">
            <div class="panel-head">
              <div>
                <p class="panel-kicker">趋势观察</p>
                <h2 id="trendTitle">近 30 天数据走势</h2>
              </div>
              <div class="metric-switch">
                ${metricOptions.map(([value, label]) => `
                  <button data-metric="${value}" class="${value === "orders" ? "active" : ""}">${label}</button>
                `).join("")}
              </div>
            </div>
            <div id="trendChart"></div>
          </article>

          <aside class="panel forecast-panel forecast-sidebar" aria-labelledby="forecastTitle">
            <div class="forecast-head">
              <div>
                <p class="panel-kicker">佣金预测与异常判断</p>
                <h2 id="forecastTitle">理论基准 vs 动态预测</h2>
                <p>固定标尺识别异常，动态模型随实际趋势每日更新</p>
              </div>
              <span class="forecast-scope" id="forecastScope">小红书渠道</span>
            </div>
            <div class="forecast-grid" id="forecastGrid"></div>
            <div class="forecast-bottom">
              <div class="forecast-status" id="forecastStatus"></div>
              <div class="forecast-method" id="forecastMethod"></div>
            </div>
          </aside>
        </section>

        <section class="panel ranking-panel">
          <div class="panel-head ranking-head">
            <div>
              <p class="panel-kicker">效率拆解</p>
              <h2>推广位表现排名</h2>
            </div>
            <label class="search-box">
              <span aria-hidden="true">⌕</span>
              <input id="promotionSearch" placeholder="搜索推广位" aria-label="搜索推广位">
            </label>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>排名</th><th>渠道 / 推广位</th><th>有效订单</th><th>成交金额</th>
                  <th>预估佣金</th><th>佣金率</th><th>客单价</th><th>订单贡献</th><th>增长趋势</th><th>数据详情</th>
                </tr>
              </thead>
              <tbody id="rankingBody"></tbody>
            </table>
          </div>
        </section>

        <section class="panel peak-panel" aria-labelledby="peakTitle">
          <div class="peak-head">
            <div>
              <p class="panel-kicker">订单时段洞察</p>
              <h2 id="peakTitle">历史模型 · 收入前三推广位</h2>
              <p>分开观察工作日、周末和近期趋势，降低单日爆量造成的误判</p>
            </div>
            <div class="peak-actions">
              <span class="peak-date" id="peakDate"></span>
              <div class="metric-switch peak-switch" aria-label="下单高峰统计口径">
                <button data-peak-segment="weekday" class="active">工作日</button>
                <button data-peak-segment="weekend">周末</button>
                <button data-peak-segment="recent14">近期 14 天</button>
              </div>
            </div>
          </div>
          <div class="peak-grid" id="peakGrid"></div>
          <div class="peak-note" id="peakNote"></div>
        </section>

        <section class="panel channel-panel channel-panel-secondary">
          <div class="panel-head compact-head">
            <div>
              <p class="panel-kicker">辅助参考</p>
              <h2>渠道贡献</h2>
            </div>
            <span class="source-count" id="sourceCount">0/12 数据源正常</span>
          </div>
          <div class="channel-list" id="channelList"></div>
          <div id="reconcileBox"></div>
        </section>

        </div>

        <section class="dashboard-view daily-view hidden" id="dailyView" aria-labelledby="dailyViewTitle">
          <div class="daily-intro">
            <div>
              <p class="panel-kicker">推广位逐日追踪</p>
              <h2 id="dailyViewTitle">每日订单与佣金明细</h2>
              <p>按日期展开每个推广位，观察出单、佣金及活动放量或回落。</p>
            </div>
            <div class="daily-filter-stack">
              <div class="segmented daily-range-tabs" aria-label="每日明细时间范围">
                ${[[7, "近 7 天"], [14, "近 14 天"], [30, "近 30 天"]].map(([value, label]) => `
                  <button data-daily-range="${value}" class="${value === 14 ? "active" : ""}">${label}</button>
                `).join("")}
              </div>
              <label class="search-box daily-search">
                <span aria-hidden="true">⌕</span>
                <input id="dailySearch" placeholder="搜索推广位" aria-label="搜索每日推广位">
              </label>
            </div>
          </div>

          <section class="daily-control-row panel" aria-label="每日明细筛选">
            <div>
              <span>渠道</span>
              <div class="segmented compact-segmented">
                ${["全部", "小红书", "企业微信"].map((value) => `<button data-daily-channel="${value}" class="${value === "小红书" ? "active" : ""}">${value}</button>`).join("")}
              </div>
            </div>
            <div>
              <span>推广位排序</span>
              <div class="segmented compact-segmented">
                <button data-daily-sort="orders" class="active">按订单</button>
                <button data-daily-sort="commission">按佣金</button>
              </div>
            </div>
            <div>
              <span>查看方式</span>
              <div class="segmented compact-segmented">
                <button data-daily-layout="matrix" class="active">横向对比</button>
                <button data-daily-layout="list">展开明细</button>
              </div>
            </div>
            <small id="dailySortFeedback">推广位列按所选范围订单从高到低排列</small>
          </section>

          <section class="daily-kpi-grid" id="dailyKpis" aria-label="每日明细汇总"></section>

          <section class="panel daily-insight-panel">
            <div class="panel-head">
              <div><p class="panel-kicker">辅助观察</p><h2>推广位变化提示</h2></div>
              <span class="daily-scope" id="dailyScope"></span>
            </div>
            <div class="daily-insight-grid" id="dailyInsights"></div>
          </section>

          <section class="panel daily-table-panel">
            <div class="panel-head daily-table-head">
              <div>
                <p class="panel-kicker">逐日明细</p>
                <h2>日期 × 推广位数据表</h2>
              </div>
              <div class="daily-table-actions">
                <div class="signal-legend"><span class="surge">放量</span><span class="drop">回落</span><span class="new">新增</span><span class="steady">平稳</span></div>
                <div class="matrix-scroll-controls" id="matrixScrollControls">
                  <button type="button" data-matrix-scroll="-1" aria-label="向左查看更多推广位">←</button>
                  <span><strong>还有更多推广位</strong><small>点击箭头或拖动下方蓝色滚动条</small></span>
                  <button type="button" data-matrix-scroll="1" aria-label="向右查看更多推广位">→</button>
                </div>
              </div>
            </div>
            <div class="daily-matrix-wrap" id="dailyMatrixScroll">
              <table class="daily-matrix-table">
                <thead id="dailyMatrixHead"></thead>
                <tbody id="dailyMatrixBody"></tbody>
              </table>
            </div>
            <div class="table-wrap daily-table-wrap hidden" id="dailyListView">
              <table class="daily-data-table">
                <thead><tr><th>日期 / 推广位</th><th>渠道</th><th>有效订单</th><th>成交金额</th><th>预估佣金</th><th>佣金率</th><th>日环比</th><th>变化信号</th></tr></thead>
                <tbody id="dailyTableBody"></tbody>
              </table>
            </div>
          </section>
        </section>

        <footer>
          <div><span class="live-dot"></span> 数据来自云瞻公开推广看板 · 每 5 分钟自动刷新</div>
          <span>统计口径：有效下单 / 有效预估佣金 / 有效成交金额</span>
        </footer>
      </main>
    `;
  }

  function showDashboard() {
    app.innerHTML = dashboardTemplate();
    bindDashboardControls();
    renderAll();
    void refreshData();
    clearInterval(state.timer);
    state.timer = window.setInterval(() => void refreshData(), REFRESH_MS);
  }

  function bindDashboardControls() {
    document.querySelectorAll("[data-view]").forEach((button) => {
      button.addEventListener("click", () => {
        state.view = button.dataset.view;
        renderViewVisibility();
        if (state.view === "daily") renderDailyView();
      });
    });
    document.querySelectorAll("[data-channel]").forEach((button) => {
      button.addEventListener("click", () => {
        state.channel = button.dataset.channel;
        document.querySelectorAll("[data-channel]").forEach((item) => {
          item.classList.toggle("active", item === button);
        });
        renderAll();
      });
    });
    document.querySelectorAll("[data-period]").forEach((button) => {
      button.addEventListener("click", () => {
        state.period = button.dataset.period;
        document.querySelectorAll("[data-period]").forEach((item) => {
          item.classList.toggle("active", item === button);
        });
        renderAll();
      });
    });
    document.querySelectorAll("[data-metric]").forEach((button) => {
      button.addEventListener("click", () => {
        state.trendMetric = button.dataset.metric;
        document.querySelectorAll("[data-metric]").forEach((item) => {
          item.classList.toggle("active", item === button);
        });
        renderTrend();
      });
    });
    document.querySelectorAll("[data-peak-segment]").forEach((button) => {
      button.addEventListener("click", () => {
        state.peakSegment = button.dataset.peakSegment;
        document.querySelectorAll("[data-peak-segment]").forEach((item) => {
          item.classList.toggle("active", item === button);
        });
        renderOrderPeaks();
      });
    });
    document.getElementById("promotionSearch")?.addEventListener("input", (event) => {
      state.search = event.target.value;
      renderRanking();
    });
    document.querySelectorAll("[data-daily-range]").forEach((button) => {
      button.addEventListener("click", () => {
        state.dailyRange = number(button.dataset.dailyRange);
        document.querySelectorAll("[data-daily-range]").forEach((item) => item.classList.toggle("active", item === button));
        state.expandedDates.clear();
        state.dailyExpansionReady = false;
        renderDailyView();
      });
    });
    document.querySelectorAll("[data-daily-channel]").forEach((button) => {
      button.addEventListener("click", () => {
        state.dailyChannel = button.dataset.dailyChannel;
        document.querySelectorAll("[data-daily-channel]").forEach((item) => item.classList.toggle("active", item === button));
        state.expandedDates.clear();
        state.dailyExpansionReady = false;
        renderDailyView();
      });
    });
    document.querySelectorAll("[data-daily-sort]").forEach((button) => {
      button.addEventListener("click", () => {
        state.dailySort = button.dataset.dailySort;
        document.querySelectorAll("[data-daily-sort]").forEach((item) => item.classList.toggle("active", item === button));
        renderDailyView();
      });
    });
    document.querySelectorAll("[data-daily-layout]").forEach((button) => {
      button.addEventListener("click", () => {
        state.dailyLayout = button.dataset.dailyLayout;
        document.querySelectorAll("[data-daily-layout]").forEach((item) => item.classList.toggle("active", item === button));
        renderDailyLayoutVisibility();
      });
    });
    document.querySelectorAll("[data-matrix-scroll]").forEach((button) => {
      button.addEventListener("click", () => {
        const container = document.getElementById("dailyMatrixScroll");
        if (!container) return;
        const direction = number(button.dataset.matrixScroll) || 1;
        container.scrollBy({ left: direction * Math.max(420, container.clientWidth * 0.72), behavior: "smooth" });
      });
    });
    document.getElementById("dailySearch")?.addEventListener("input", (event) => {
      state.dailySearch = event.target.value;
      state.expandedDates.clear();
      state.dailyExpansionReady = false;
      renderDailyView();
    });
    document.getElementById("refreshButton")?.addEventListener("click", () => {
      void refreshData();
    });
    document.getElementById("rankingBody")?.addEventListener("click", (event) => {
      const button = event.target.closest("[data-detail-id]");
      if (button) openPromotionDetail(button.dataset.detailId);
    });
    document.getElementById("dailyTableBody")?.addEventListener("click", (event) => {
      const toggle = event.target.closest("[data-date-toggle]");
      if (!toggle) return;
      const date = toggle.dataset.dateToggle;
      if (state.expandedDates.has(date)) state.expandedDates.delete(date);
      else state.expandedDates.add(date);
      renderDailyTable();
    });
  }

  const zeroMetrics = () => ({ orders: 0, commission: 0, gmv: 0 });

  function addMetrics(target, value) {
    target.orders += value.orders;
    target.commission += value.commission;
    target.gmv += value.gmv;
    return target;
  }

  function monthKey(monthOffset = 0) {
    const [year, month] = shanghaiDateKey().split("-").map(Number);
    return new Date(Date.UTC(year, month - 1 - monthOffset, 1)).toISOString().slice(0, 7);
  }

  function monthBounds(monthOffset = 0) {
    const key = monthKey(monthOffset);
    const [year, month] = key.split("-").map(Number);
    const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
    return { start: `${key}-01`, end: `${key}-${String(lastDay).padStart(2, "0")}` };
  }

  function completeMonthAvailable(sources, monthOffset = 0) {
    if (!sources.length) return false;
    const { start, end } = monthBounds(monthOffset);
    return sources.every((source) => {
      const dates = new Set(source.daily.map((row) => row.date));
      return dates.has(start) && dates.has(end);
    });
  }

  function dailyRowsForPeriod(source, period, offset = 0) {
    const rows = [...source.daily].sort((left, right) => right.date.localeCompare(left.date));
    if (period === "today") return rows.filter((row) => row.date === shanghaiDateKey(-offset));
    if (period === "yesterday") return rows.filter((row) => row.date === shanghaiDateKey(-(offset + 1)));
    if (period === "month") return rows.filter((row) => row.date.startsWith(`${monthKey(offset)}-`));
    if (period === "lastMonth") return rows.filter((row) => row.date.startsWith(`${monthKey(offset + 1)}-`));
    const days = period === "7d" ? 7 : 30;
    return rows.slice(offset, offset + days);
  }

  function metricsFor(source, period, offset = 0) {
    if (period === "all") return offset === 0 ? { ...source.totals } : zeroMetrics();
    return dailyRowsForPeriod(source, period, offset)
      .reduce((sum, row) => addMetrics(sum, row), zeroMetrics());
  }

  function aggregate(sources, period, offset = 0) {
    return sources.reduce(
      (sum, source) => addMetrics(sum, metricsFor(source, period, offset)),
      zeroMetrics(),
    );
  }

  function number(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function money(value) {
    return new Intl.NumberFormat("zh-CN", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(value);
  }

  function integer(value) {
    return new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 0 }).format(value);
  }

  function compact(value) {
    if (value >= 10000) return `${(value / 10000).toFixed(1)}万`;
    if (value >= 1000) return `${(value / 1000).toFixed(1)}k`;
    return value.toFixed(value % 1 === 0 ? 0 : 2);
  }

  function ratio(current, previous) {
    if (!previous) return current > 0 ? null : 0;
    return ((current - previous) / previous) * 100;
  }

  function updateTime(iso) {
    if (!iso) return "等待同步";
    return new Intl.DateTimeFormat("zh-CN", {
      timeZone: "Asia/Shanghai",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(new Date(iso));
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[character]);
  }

  function safeExternalUrl(value) {
    try {
      const url = new URL(value);
      return url.protocol === "https:" ? url.href : "#";
    } catch {
      return "#";
    }
  }

  function selectedSources() {
    return (state.data?.sources || []).filter(
      (source) => state.channel === "全部" || source.channel === state.channel,
    );
  }

  function dashboardMetrics() {
    const visible = selectedSources();
    const totals = visible.filter((source) => source.kind === "channel");
    const current = aggregate(totals, state.period);
    let previous = zeroMetrics();
    if (state.period === "today") previous = aggregate(totals, "today", 1);
    if (state.period === "yesterday") previous = aggregate(totals, "today", 2);
    if (state.period === "7d") previous = aggregate(totals, "7d", 7);
    if (state.period === "lastMonth") previous = aggregate(totals, "lastMonth", 1);
    const periodComplete = state.period !== "lastMonth" || completeMonthAvailable(totals, 1);
    const comparisonAvailable = state.period !== "lastMonth"
      || (periodComplete && completeMonthAvailable(totals, 2));
    return { visible, totals, current, previous, periodComplete, comparisonAvailable };
  }

  async function fetchSource(source) {
    const parameters = new URLSearchParams({
      accountsid: state.config.accountId,
      ...source.query,
    });
    const response = await fetch(`${state.config.apiBase}?${parameters}`, {
      cache: "no-store",
      credentials: "omit",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error(`数据源响应异常：${response.status}`);
    const payload = JSON.parse(await response.text());
    if (payload.code !== 200 || !payload.data) {
      throw new Error(payload.message || "数据源返回异常");
    }
    const total = payload.data.statistics_total || {};
    return {
      id: source.id,
      channel: source.channel,
      promotion: source.promotion,
      kind: source.kind,
      shortUrl: source.shortUrl,
      totals: {
        orders: number(total.valid_num),
        commission: number(total.estimate_valid_amount),
        gmv: number(total.valid_amount),
      },
      daily: (payload.data.statistics_list || []).map((row) => ({
        date: row.statistics_date,
        orders: number(row.valid_num),
        commission: number(row.estimate_valid_amount),
        gmv: number(row.valid_amount),
      })),
      status: "ok",
    };
  }

  async function refreshData() {
    if (state.loading) return;
    state.loading = true;
    state.error = "";
    state.usingCache = false;
    setSyncState();
    try {
      const previous = new Map((state.data?.sources || []).map((source) => [source.id, source]));
      const settled = await Promise.allSettled(state.config.sources.map(fetchSource));
      const sources = settled.map((result, index) => {
        if (result.status === "fulfilled") return result.value;
        const definition = state.config.sources[index];
        const old = previous.get(definition.id);
        if (old?.status === "ok") {
          return { ...old, status: "error", error: "本次刷新失败，已保留上次数据" };
        }
        return {
          ...definition,
          totals: zeroMetrics(),
          daily: [],
          status: "error",
          error: result.reason instanceof Error ? result.reason.message : "读取失败",
        };
      });
      const successful = sources.filter((source) => source.status === "ok").length;
      if (!successful) throw new Error("全部数据源暂时无法连接");
      state.data = { refreshedAt: new Date().toISOString(), sources };
      if (successful < sources.length) {
        state.error = `${sources.length - successful} 个数据源本次刷新失败，已保留可用数据`;
      }
      await saveEncryptedCache(state.data);
    } catch (error) {
      if (!state.data) {
        const cached = await loadEncryptedCache();
        if (cached) {
          state.data = cached;
          state.usingCache = true;
          state.error = "实时数据暂时无法连接，当前显示本设备上次成功同步的数据";
        } else {
          state.error = error instanceof Error ? error.message : "读取数据失败";
        }
      } else {
        state.error = "实时刷新失败，当前保留上一次成功读取的数据";
      }
    } finally {
      state.loading = false;
      setSyncState();
      renderAll();
    }
  }

  function setSyncState() {
    const title = document.getElementById("syncTitle");
    const time = document.getElementById("syncTime");
    const dot = document.getElementById("liveDot");
    const button = document.getElementById("refreshButton");
    const icon = document.getElementById("refreshIcon");
    const label = document.getElementById("refreshLabel");
    if (!title || !time || !dot || !button || !icon || !label) return;
    button.disabled = state.loading;
    icon.classList.toggle("spin", state.loading);
    label.textContent = state.loading ? "同步中" : "立即刷新";
    dot.classList.toggle("is-error", Boolean(state.error));
    title.textContent = state.loading
      ? "数据同步中"
      : state.error
        ? state.usingCache ? "正在使用缓存" : "部分同步异常"
        : "数据已连接";
    time.textContent = state.data
      ? `更新于 ${updateTime(state.data.refreshedAt)} · 每 5 分钟自动刷新`
      : "正在读取最新数据";
  }

  function renderAll() {
    renderViewVisibility();
    renderError();
    renderKpis();
    renderTrend();
    renderChannels();
    renderRanking();
    renderForecast();
    renderOrderPeaks();
    renderDailyView();
    setSyncState();
  }

  function renderViewVisibility() {
    const overview = document.getElementById("overviewView");
    const daily = document.getElementById("dailyView");
    if (!overview || !daily) return;
    overview.classList.toggle("hidden", state.view !== "overview");
    daily.classList.toggle("hidden", state.view !== "daily");
    document.querySelectorAll("[data-view]").forEach((button) => {
      button.classList.toggle("active", button.dataset.view === state.view);
    });
  }

  function renderError() {
    const banner = document.getElementById("errorBanner");
    if (!banner) return;
    banner.textContent = state.error;
    banner.classList.toggle("hidden", !state.error);
  }

  function shiftDateKey(dateKey, days) {
    const date = new Date(`${dateKey}T00:00:00Z`);
    date.setUTCDate(date.getUTCDate() + days);
    return date.toISOString().slice(0, 10);
  }

  function readableDate(dateKey) {
    const date = new Date(`${dateKey}T00:00:00Z`);
    const weekday = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"][date.getUTCDay()];
    return `${shortDateLabel(dateKey)} · ${weekday}`;
  }

  function dailyPromotionSources() {
    const query = state.dailySearch.trim().toLowerCase();
    return (state.data?.sources || []).filter((source) =>
      source.kind === "promotion"
      && (state.dailyChannel === "全部" || source.channel === state.dailyChannel)
      && (!query || `${source.channel}${source.promotion}`.toLowerCase().includes(query)));
  }

  function dailyDateKeys(sources) {
    return [...new Set(sources.flatMap((source) => source.daily.map((row) => row.date)))]
      .sort((left, right) => right.localeCompare(left))
      .slice(0, state.dailyRange);
  }

  function sourceMetricsOnDate(source, dateKey) {
    const row = source.daily.find((item) => item.date === dateKey);
    return row ? { orders: number(row.orders), commission: number(row.commission), gmv: number(row.gmv) } : zeroMetrics();
  }

  function metricsForDate(sources, dateKey) {
    return sources.reduce((total, source) => addMetrics(total, sourceMetricsOnDate(source, dateKey)), zeroMetrics());
  }

  function metricsForDates(source, dates) {
    return dates.reduce((total, dateKey) => addMetrics(total, sourceMetricsOnDate(source, dateKey)), zeroMetrics());
  }

  function activitySignal(source, dateKey, current) {
    const history = Array.from({ length: 7 }, (_, index) => sourceMetricsOnDate(source, shiftDateKey(dateKey, -(index + 1))));
    const averageOrders = history.reduce((sum, item) => sum + item.orders, 0) / 7;
    const rate = current.gmv ? (current.commission / current.gmv) * 100 : 0;
    if (current.orders > 0 && averageOrders === 0) return { tone: "new", label: "新增出单", note: "前 7 天无订单" };
    if (current.orders >= Math.max(3, averageOrders * 1.8)) return { tone: "surge", label: "明显放量", note: `高于前 7 天日均 ${averageOrders ? Math.round(((current.orders / averageOrders) - 1) * 100) : 0}%` };
    if (averageOrders >= 2 && current.orders <= averageOrders * .45) return { tone: "drop", label: "明显回落", note: `前 7 天日均 ${averageOrders.toFixed(1)} 单` };
    if (current.orders > 0 && rate >= 8) return { tone: "high", label: "高佣表现", note: `佣金率 ${rate.toFixed(1)}%` };
    if (current.orders > 0) return { tone: "steady", label: "相对平稳", note: `前 7 天日均 ${averageOrders.toFixed(1)} 单` };
    return { tone: "none", label: "暂无订单", note: "当日未出单" };
  }

  function trendMiniBars(source, dateKey) {
    const values = Array.from({ length: 7 }, (_, index) => sourceMetricsOnDate(source, shiftDateKey(dateKey, index - 6)).orders);
    const maximum = Math.max(...values, 1);
    return `<span class="mini-trend" title="截至当日近 7 天订单：${values.join("、")}">${values.map((value) => `<i style="height:${Math.max(value ? 18 : 4, (value / maximum) * 100)}%"></i>`).join("")}</span>`;
  }

  function dailyRangeStats(sources, dates) {
    return sources.map((source) => ({ ...source, rangeMetrics: metricsForDates(source, dates) }));
  }

  function sortedDailySources(sources, dates) {
    const key = state.dailySort === "commission" ? "commission" : "orders";
    return dailyRangeStats(sources, dates).sort((left, right) =>
      right.rangeMetrics[key] - left.rangeMetrics[key]
      || right.rangeMetrics.orders - left.rangeMetrics.orders
      || left.promotion.localeCompare(right.promotion, "zh-CN"));
  }

  function renderDailyLayoutVisibility() {
    const matrix = document.getElementById("dailyMatrixScroll");
    const list = document.getElementById("dailyListView");
    const controls = document.getElementById("matrixScrollControls");
    const isMatrix = state.dailyLayout === "matrix";
    matrix?.classList.toggle("hidden", !isMatrix);
    list?.classList.toggle("hidden", isMatrix);
    controls?.classList.toggle("hidden", !isMatrix);
  }

  function renderDailyMatrix(sources, dates) {
    const head = document.getElementById("dailyMatrixHead");
    const body = document.getElementById("dailyMatrixBody");
    if (!head || !body) return;
    const sorted = sortedDailySources(sources, dates);
    if (!sorted.length || !dates.length) {
      head.innerHTML = "";
      body.innerHTML = '<tr><td><div class="table-empty">当前筛选下暂无每日数据</div></td></tr>';
      return;
    }
    head.innerHTML = `<tr><th><span>日期</span><small>新 → 旧</small></th>${sorted.map((source, index) => `
      <th title="${escapeHtml(source.promotion)}">
        <div class="matrix-promotion-head"><span>${String(index + 1).padStart(2, "0")}</span><strong>${escapeHtml(source.promotion)}</strong></div>
        <small>${integer(source.rangeMetrics.orders)} 单 · ¥${money(source.rangeMetrics.commission)}</small>
      </th>`).join("")}</tr>`;
    const totalRow = `<tr class="matrix-total-row"><td><strong>范围合计</strong><small>${dates.length} 个自然日</small></td>${sorted.map((source) => `
      <td><b>${integer(source.rangeMetrics.orders)} 单</b><strong>¥ ${money(source.rangeMetrics.commission)}</strong></td>`).join("")}</tr>`;
    const dayRows = dates.map((dateKey) => {
      const dayTotal = metricsForDate(sources, dateKey);
      return `<tr><td><strong>${readableDate(dateKey)}</strong><small>${integer(dayTotal.orders)} 单 · ¥${money(dayTotal.commission)}</small></td>${sorted.map((source) => {
        const current = sourceMetricsOnDate(source, dateKey);
        const signal = activitySignal(source, dateKey, current);
        return `<td class="matrix-value ${signal.tone}" title="${escapeHtml(signal.note)}"><b>${integer(current.orders)} 单</b><strong>¥ ${money(current.commission)}</strong><small>${signal.label}</small></td>`;
      }).join("")}</tr>`;
    }).join("");
    body.innerHTML = totalRow + dayRows;
  }

  function renderDailyKpis(sources, dates) {
    const grid = document.getElementById("dailyKpis");
    if (!grid) return;
    const rows = dailyRangeStats(sources, dates);
    const total = rows.reduce((sum, row) => addMetrics(sum, row.rangeMetrics), zeroMetrics());
    const active = rows.filter((row) => row.rangeMetrics.orders > 0).length;
    const dailyAverage = dates.length ? total.orders / dates.length : 0;
    const items = [
      ["推广位有效订单", `${integer(total.orders)} 笔`, `${integer(active)} 个推广位出单`, "blue"],
      ["推广位预估佣金", `¥ ${money(total.commission)}`, `${dates.length} 个自然日`, "red"],
      ["日均订单", `${dailyAverage.toFixed(1)} 笔`, "用于识别整体节奏变化", "green"],
      ["综合佣金率", total.gmv ? `${((total.commission / total.gmv) * 100).toFixed(2)}%` : "0.00%", `成交 ¥${money(total.gmv)}`, "gold"],
    ];
    grid.innerHTML = items.map(([label, value, note, tone]) => `
      <article class="daily-kpi ${tone}"><span>${label}</span><strong>${value}</strong><small>${note}</small></article>
    `).join("");
  }

  function renderDailyInsights(sources, dates) {
    const grid = document.getElementById("dailyInsights");
    const scope = document.getElementById("dailyScope");
    if (!grid || !scope) return;
    scope.textContent = `${state.dailyChannel} · ${dates.length ? `${shortDateLabel(dates.at(-1))}—${shortDateLabel(dates[0])}` : "暂无数据"}`;
    if (!sources.length || !dates.length) {
      grid.innerHTML = '<div class="daily-empty">当前筛选下暂无推广位数据</div>';
      return;
    }
    const rangeRows = dailyRangeStats(sources, dates);
    const topCommission = [...rangeRows].sort((a, b) => b.rangeMetrics.commission - a.rangeMetrics.commission)[0];
    const topRate = [...rangeRows].filter((row) => row.rangeMetrics.gmv > 0)
      .sort((a, b) => (b.rangeMetrics.commission / b.rangeMetrics.gmv) - (a.rangeMetrics.commission / a.rangeMetrics.gmv))[0];
    const latestDate = dates[0];
    const growthRows = sources.map((source) => {
      const recentDates = Array.from({ length: 7 }, (_, index) => shiftDateKey(latestDate, -index));
      const priorDates = Array.from({ length: 7 }, (_, index) => shiftDateKey(latestDate, -(index + 7)));
      const recent = metricsForDates(source, recentDates);
      const prior = metricsForDates(source, priorDates);
      return { source, recent, prior, growth: ratio(recent.orders, prior.orders) };
    }).filter((row) => row.recent.orders >= 3 && row.growth !== null)
      .sort((a, b) => b.growth - a.growth);
    const fastest = growthRows[0];
    const latestSignals = sources.map((source) => ({ source, current: sourceMetricsOnDate(source, latestDate) }))
      .map((item) => ({ ...item, signal: activitySignal(item.source, latestDate, item.current) }));
    const alertCount = latestSignals.filter((item) => ["surge", "drop", "new"].includes(item.signal.tone)).length;
    const items = [
      ["近 7 天增长最快", fastest?.source.promotion || "暂无可比数据", fastest ? `${fastest.growth >= 0 ? "+" : ""}${fastest.growth.toFixed(1)}% · ${integer(fastest.recent.orders)} 单` : "需继续积累订单", "growth"],
      ["范围内佣金贡献最高", topCommission?.promotion || "暂无数据", topCommission ? `¥${money(topCommission.rangeMetrics.commission)} · ${integer(topCommission.rangeMetrics.orders)} 单` : "—", "commission"],
      ["范围内佣金率最高", topRate?.promotion || "暂无数据", topRate ? `${((topRate.rangeMetrics.commission / topRate.rangeMetrics.gmv) * 100).toFixed(2)}% · 成交 ¥${money(topRate.rangeMetrics.gmv)}` : "—", "rate"],
      ["最近一天变化提醒", `${integer(alertCount)} 个推广位`, alertCount ? "展开最近日期查看放量、回落或新增" : "整体未见明显异常", "alert"],
    ];
    grid.innerHTML = items.map(([label, value, note, tone]) => `
      <article class="daily-insight ${tone}"><span>${label}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(note)}</small></article>
    `).join("");
  }

  function renderDailyTable() {
    const body = document.getElementById("dailyTableBody");
    if (!body) return;
    const sources = dailyPromotionSources();
    const dates = dailyDateKeys(sources);
    if (!state.dailyExpansionReady && dates[0]) {
      state.expandedDates.add(dates[0]);
      state.dailyExpansionReady = true;
    }
    if (!sources.length || !dates.length) {
      body.innerHTML = '<tr><td colspan="8"><div class="table-empty">当前筛选下暂无每日数据</div></td></tr>';
      return;
    }
    const sorted = sortedDailySources(sources, dates);
    body.innerHTML = dates.map((dateKey) => {
      const expanded = state.expandedDates.has(dateKey);
      const total = metricsForDate(sources, dateKey);
      const previous = metricsForDate(sources, shiftDateKey(dateKey, -1));
      const dayGrowth = ratio(total.orders, previous.orders);
      const active = sources.filter((source) => sourceMetricsOnDate(source, dateKey).orders > 0).length;
      const dayTone = dayGrowth === null || Math.abs(dayGrowth) < 30 ? "steady" : dayGrowth >= 30 ? "surge" : "drop";
      const dayLabel = dayGrowth === null ? "新增" : `${dayGrowth > 0 ? "+" : ""}${dayGrowth.toFixed(1)}%`;
      const detailRows = expanded ? sorted.map((source) => {
        const current = sourceMetricsOnDate(source, dateKey);
        const prior = sourceMetricsOnDate(source, shiftDateKey(dateKey, -1));
        const change = ratio(current.orders, prior.orders);
        const signal = activitySignal(source, dateKey, current);
        const changeText = change === null ? (current.orders ? "新增" : "—") : `${change > 0 ? "+" : ""}${change.toFixed(1)}%`;
        const changeTone = change > 0 ? "up" : change < 0 ? "down" : "flat";
        return `
          <tr class="daily-promotion-row">
            <td><div class="daily-promotion"><span class="${source.channel === "小红书" ? "xhs-bg" : "wecom-bg"}">${source.channel === "小红书" ? "小" : "企"}</span><div><strong>${escapeHtml(source.promotion)}</strong>${trendMiniBars(source, dateKey)}</div></div></td>
            <td><small class="daily-channel-label">${escapeHtml(source.channel)}</small></td>
            <td><b>${integer(current.orders)}</b></td>
            <td>¥ ${money(current.gmv)}</td>
            <td><strong class="daily-commission">¥ ${money(current.commission)}</strong></td>
            <td>${current.gmv ? `${((current.commission / current.gmv) * 100).toFixed(2)}%` : "—"}</td>
            <td><span class="daily-change ${changeTone}">${changeText}</span></td>
            <td><span class="activity-signal ${signal.tone}" title="${escapeHtml(signal.note)}">${signal.label}</span></td>
          </tr>`;
      }).join("") : "";
      return `
        <tr class="daily-date-row ${expanded ? "expanded" : ""}">
          <td><button type="button" data-date-toggle="${dateKey}" aria-expanded="${expanded}"><i>${expanded ? "−" : "+"}</i><span><strong>${readableDate(dateKey)}</strong><small>${expanded ? "收起推广位" : "展开全部推广位"}</small></span></button></td>
          <td><span class="daily-summary-label">日汇总 · ${integer(active)} 个出单</span></td>
          <td><b>${integer(total.orders)}</b></td>
          <td>¥ ${money(total.gmv)}</td>
          <td><strong class="daily-commission">¥ ${money(total.commission)}</strong></td>
          <td>${total.gmv ? `${((total.commission / total.gmv) * 100).toFixed(2)}%` : "—"}</td>
          <td><span class="daily-change ${dayTone === "surge" ? "up" : dayTone === "drop" ? "down" : "flat"}">${dayLabel}</span></td>
          <td><span class="activity-signal ${dayTone}">${dayTone === "surge" ? "整体放量" : dayTone === "drop" ? "整体回落" : "整体平稳"}</span></td>
        </tr>${detailRows}`;
    }).join("");
  }

  function renderDailyView() {
    const sources = dailyPromotionSources();
    const dates = dailyDateKeys(sources);
    const sortFeedback = document.getElementById("dailySortFeedback");
    if (sortFeedback) sortFeedback.textContent = `推广位列按所选范围${state.dailySort === "commission" ? "佣金" : "订单"}从高到低排列`;
    renderDailyKpis(sources, dates);
    renderDailyInsights(sources, dates);
    renderDailyMatrix(sources, dates);
    renderDailyTable();
    renderDailyLayoutVisibility();
  }

  function renderKpis() {
    const grid = document.getElementById("kpiGrid");
    if (!grid) return;
    const { current, previous, periodComplete, comparisonAvailable } = dashboardMetrics();
    const canCompare = state.period === "today"
      || state.period === "yesterday"
      || state.period === "7d"
      || (state.period === "lastMonth" && comparisonAvailable);
    const compareLabel = state.period === "today"
      ? "较昨日"
      : state.period === "yesterday" ? "较前日"
        : state.period === "lastMonth" ? "较前月" : "较前 7 天";
    const neutralLabel = state.period === "lastMonth"
      ? (periodComplete ? "上月完整自然月" : "上月当前可见部分")
      : "按当前筛选范围统计";
    const kpis = [
      ["有效订单", `${integer(current.orders)} 笔`, ratio(current.orders, previous.orders), "blue"],
      ["预估佣金", `¥ ${money(current.commission)}`, ratio(current.commission, previous.commission), "red"],
      ["成交金额", `¥ ${money(current.gmv)}`, ratio(current.gmv, previous.gmv), "green"],
      ["平均客单价", current.orders ? `¥ ${money(current.gmv / current.orders)}` : "¥ 0.00", null, "gold"],
      ["预估佣金率", current.gmv ? `${((current.commission / current.gmv) * 100).toFixed(2)}%` : "0.00%", null, "violet"],
    ];
    grid.innerHTML = kpis.map(([label, value, comparison, tone]) => {
      const comparisonHtml = canCompare && comparison !== null
        ? `<span class="${comparison >= 0 ? "up" : "down"}">${comparison >= 0 ? "↑" : "↓"} ${Math.abs(comparison).toFixed(1)}%<em>${compareLabel}</em></span>`
        : `<span class="neutral">${neutralLabel}</span>`;
      return `
        <article class="kpi-card ${tone}">
          <div class="kpi-heading"><span>${label}</span><i aria-hidden="true"></i></div>
          <strong>${state.loading && !state.data ? "—" : value}</strong>
          <div class="kpi-foot">${comparisonHtml}</div>
        </article>
      `;
    }).join("");
  }

  function shanghaiDateKey(offsetDays = 0) {
    const target = new Date(Date.now() + offsetDays * 24 * 60 * 60 * 1000);
    const parts = new Intl.DateTimeFormat("zh-CN", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).formatToParts(target);
    const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
    return `${values.year}-${values.month}-${values.day}`;
  }

  function shortDateLabel(dateKey) {
    const [, month, day] = dateKey.split("-");
    return `${month}月${day}日`;
  }

  function monthContext() {
    const [year, month] = shanghaiDateKey().split("-").map(Number);
    const currentStart = `${year}-${String(month).padStart(2, "0")}-01`;
    const previousDate = new Date(Date.UTC(year, month - 2, 1));
    const previousYear = previousDate.getUTCFullYear();
    const previousMonth = previousDate.getUTCMonth() + 1;
    const previousStart = `${previousYear}-${String(previousMonth).padStart(2, "0")}-01`;
    const previousEndDay = new Date(Date.UTC(year, month - 1, 0)).getUTCDate();
    const previousEnd = `${previousYear}-${String(previousMonth).padStart(2, "0")}-${String(previousEndDay).padStart(2, "0")}`;
    return {
      currentStart,
      currentEnd: shanghaiDateKey(-1),
      previousStart,
      previousEnd,
      currentLabel: `${month}月`,
      previousLabel: `${previousMonth}月`,
    };
  }

  function metricsBetween(sources, start, end) {
    return sources.reduce((total, source) => source.daily
      .filter((row) => row.date >= start && row.date <= end)
      .reduce((sum, row) => addMetrics(sum, row), total), zeroMetrics());
  }

  function availableDateRange(sources, start, end) {
    const dates = sources.flatMap((source) => source.daily.map((row) => row.date))
      .filter((date) => date >= start && date <= end)
      .sort();
    return dates.length ? { start: dates[0], end: dates[dates.length - 1] } : null;
  }

  function metricsOnDate(source, dateKey) {
    const row = source.daily.find((item) => item.date === dateKey);
    return row ? { orders: row.orders, commission: row.commission, gmv: row.gmv } : null;
  }

  function comparisonDay(sources, dateKey) {
    return sources.reduce((result, source) => {
      const metrics = metricsOnDate(source, dateKey);
      if (metrics) {
        addMetrics(result.metrics, metrics);
        result.available += 1;
      }
      return result;
    }, { metrics: zeroMetrics(), available: 0 });
  }

  function comparisonValue(current, previous) {
    const change = ratio(current, previous);
    if (change === null) return { tone: "new", label: "新增" };
    if (change === 0) return { tone: "flat", label: "持平" };
    return {
      tone: change > 0 ? "up" : "down",
      label: `${change > 0 ? "↑" : "↓"} ${Math.abs(change).toFixed(1)}%`,
    };
  }

  function startOfWeek(dateKey) {
    const [year, month, day] = dateKey.split("-").map(Number);
    const date = new Date(Date.UTC(year, month - 1, day));
    const weekday = date.getUTCDay() || 7;
    date.setUTCDate(date.getUTCDate() - weekday + 1);
    return date.toISOString().slice(0, 10);
  }

  function endOfMonth(dateKey) {
    const [year, month] = dateKey.split("-").map(Number);
    return new Date(Date.UTC(year, month, 0)).toISOString().slice(0, 10);
  }

  function daysBetweenInclusive(start, end) {
    const left = Date.parse(`${start}T00:00:00Z`);
    const right = Date.parse(`${end}T00:00:00Z`);
    return Math.max(0, Math.round((right - left) / 86400000) + 1);
  }

  function commissionBetween(source, start, end) {
    return source.daily
      .filter((row) => row.date >= start && row.date <= end)
      .reduce((sum, row) => sum + row.commission, 0);
  }

  function forecastAmount(value) {
    return `¥ ${money(Math.max(0, value))}`;
  }

  function renderForecast() {
    const grid = document.getElementById("forecastGrid");
    const status = document.getElementById("forecastStatus");
    const method = document.getElementById("forecastMethod");
    const scope = document.getElementById("forecastScope");
    if (!grid || !status || !method || !scope) return;

    const source = (state.data?.sources || []).find((item) => item.id === "xhs-total");
    const baseline = state.config?.forecastBaseline;
    scope.textContent = "小红书渠道 · 不受上方渠道筛选影响";
    if (!source || !baseline) {
      grid.innerHTML = '<div class="forecast-empty">正在建立佣金预测模型…</div>';
      status.textContent = "等待小红书渠道数据";
      method.textContent = "";
      return;
    }

    const today = shanghaiDateKey();
    const yesterday = shanghaiDateKey(-1);
    const weekStart = startOfWeek(today);
    const monthStart = `${today.slice(0, 8)}01`;
    const monthEnd = endOfMonth(today);
    const elapsedWeekDays = Math.max(1, daysBetweenInclusive(weekStart, today));
    const remainingWeekDays = Math.max(0, 7 - elapsedWeekDays);
    const elapsedMonthDays = Math.max(1, Number(today.slice(8, 10)));
    const totalMonthDays = Number(monthEnd.slice(8, 10));
    const remainingMonthDays = Math.max(0, totalMonthDays - elapsedMonthDays);

    const completeRows = source.daily.filter((row) => row.date <= yesterday);
    const recent7 = completeRows.slice(0, 7).reduce((sum, row) => sum + row.commission, 0);
    const prior7 = completeRows.slice(7, 14).reduce((sum, row) => sum + row.commission, 0);
    const recent14Daily = completeRows.slice(0, 14).reduce((sum, row) => sum + row.commission, 0) / Math.max(1, Math.min(14, completeRows.length));
    const recent7Daily = recent7 / Math.max(1, Math.min(7, completeRows.length));
    const momentum = prior7 > 0 ? Math.max(.65, Math.min(1.55, recent7 / prior7)) : 1;
    const dynamicDaily = (recent7Daily * .7 + recent14Daily * .3) * Math.pow(momentum, 1 / 14);

    const frozenAt = baseline.frozenAt;
    const weeksSinceFreeze = Math.max(0, daysBetweenInclusive(frozenAt, today) - 1) / 7;
    const theoreticalWeekly = baseline.weeklyBaseCommission * Math.pow(1 + baseline.weeklyGrowthRate, weeksSinceFreeze);
    const theoreticalDaily = theoreticalWeekly / 7;
    const actualWeek = commissionBetween(source, weekStart, today);
    const actualMonth = commissionBetween(source, monthStart, today);

    const theoretical = {
      tomorrow: theoreticalDaily,
      week: theoreticalWeekly,
      nextWeek: theoreticalWeekly * (1 + baseline.weeklyGrowthRate),
      month: theoreticalDaily * totalMonthDays,
    };
    const dynamic = {
      tomorrow: dynamicDaily,
      week: actualWeek + dynamicDaily * remainingWeekDays,
      nextWeek: dynamicDaily * 7 * Math.pow(momentum, .5),
      month: actualMonth + dynamicDaily * remainingMonthDays,
    };

    const items = [
      ["明日佣金", theoretical.tomorrow, dynamic.tomorrow, "未来 1 天"],
      ["本周最终", theoretical.week, dynamic.week, `已发生 ${forecastAmount(actualWeek)}`],
      ["下周佣金", theoretical.nextWeek, dynamic.nextWeek, "未来完整 7 天"],
      ["本月最终", theoretical.month, dynamic.month, `已发生 ${forecastAmount(actualMonth)}`],
    ];
    grid.innerHTML = items.map(([label, fixed, rolling, note]) => {
      const gap = fixed ? ((rolling - fixed) / fixed) * 100 : 0;
      const tone = gap > 15 ? "above" : gap < -15 ? "below" : "normal";
      return `
        <article class="forecast-card ${tone}">
          <div class="forecast-card-head"><span>${label}</span><em>${note}</em></div>
          <div class="forecast-values">
            <div><small>理论基准</small><b>${forecastAmount(fixed)}</b></div>
            <div><small>动态预测</small><strong>${forecastAmount(rolling)}</strong></div>
          </div>
          <p>${gap >= 0 ? "高于" : "低于"}基准 ${Math.abs(gap).toFixed(1)}%</p>
        </article>
      `;
    }).join("");

    const performanceGap = theoreticalDaily ? ((recent7Daily - theoreticalDaily) / theoreticalDaily) * 100 : 0;
    const statusTone = performanceGap > 20 ? "above" : performanceGap < -20 ? "below" : "normal";
    const statusTitle = statusTone === "above" ? "近期显著高于理论" : statusTone === "below" ? "近期低于理论基准" : "近期处于正常区间";
    const suggestion = statusTone === "above"
      ? "检查近期是否有高佣活动、新增推广位或爆款笔记；若活动结束，动态预测可能回落。"
      : statusTone === "below"
        ? "优先检查笔记曝光、点击转化、活动失效及高贡献推广位下滑，并安排内容优化。"
        : "继续保持当前发布节奏，重点观察动态预测是否连续 3 天偏离理论基准。";
    status.className = `forecast-status ${statusTone}`;
    status.innerHTML = `<span></span><div><strong>${statusTitle}</strong><p>近 7 个完整自然日日均佣金 ${forecastAmount(recent7Daily)}，相对理论日均 ${performanceGap >= 0 ? "+" : ""}${performanceGap.toFixed(1)}%。${suggestion}</p></div>`;
    method.innerHTML = `
      <strong>模型口径</strong>
      <p><b>理论基准：</b>${shortDateLabel(baseline.frozenAt)}冻结，基准周佣金 ${forecastAmount(baseline.weeklyBaseCommission)}，稳健周增长率 ${(baseline.weeklyGrowthRate * 100).toFixed(0)}%。</p>
      <p><b>动态预测：</b>近 7 天日均占 70% + 近 14 天日均占 30%，并用近两周动量修正；每日刷新。</p>
      <small>预测用于经营判断，不等同于平台结算承诺；高佣活动和新笔记爆发会造成短期偏离。</small>
    `;
  }

  function peakWindow(hours) {
    const windows = hours.map((value, index) => value + hours[(index + 1) % 24]);
    const start = windows.reduce(
      (best, value, index) => value > windows[best] ? index : best,
      0,
    );
    return { start, orders: windows[start] };
  }

  function hourLabel(hour) {
    return `${String((hour + 24) % 24).padStart(2, "0")}:00`;
  }

  function peakConfidence(segment) {
    if (segment.activeDays >= 10 && segment.orders >= 100) return { tone: "high", label: "样本充足" };
    if (segment.activeDays >= 5 && segment.orders >= 30) return { tone: "medium", label: "样本一般" };
    return { tone: "low", label: "样本较少" };
  }

  function peakAdvice(start, confidence) {
    if (confidence === "low") return "当前分组样本较少，建议继续积累后再调整时段";
    return `建议 ${hourLabel(start - 2)}—${hourLabel(start)} 完成笔记发布或加热`;
  }

  function segmentLabel(key) {
    return { weekday: "工作日常态", weekend: "周末常态", recent14: "近期 14 天" }[key] || "历史常态";
  }

  function latestPeakStatus(latest) {
    if (!latest?.orders) return { tone: "normal", text: "最近一天暂无订单" };
    const volumeAnomaly = latest.volumeRatio >= 2.5;
    const timeAnomaly = latest.peakShiftHours >= 5;
    if (volumeAnomaly && timeAnomaly) return { tone: "anomaly", text: "最近一天量级与时段均显著偏离常态" };
    if (volumeAnomaly) return { tone: "anomaly", text: "最近一天量级异常放大，但高峰时段与常态一致" };
    if (timeAnomaly) return { tone: "anomaly", text: `最近一天高峰偏离常态 ${integer(latest.peakShiftHours)} 小时，疑似短期波动` };
    return { tone: "normal", text: "最近一天高峰与同类日期常态基本一致" };
  }

  function renderOrderPeaks() {
    const grid = document.getElementById("peakGrid");
    const date = document.getElementById("peakDate");
    const note = document.getElementById("peakNote");
    if (!grid || !date || !note) return;

    const snapshot = state.config?.orderPeakSnapshot;
    if (!snapshot?.promotions?.length) {
      grid.innerHTML = '<div class="peak-empty">等待导入订单明细后生成时段洞察</div>';
      date.textContent = "暂无订单明细";
      note.textContent = "该板块只使用真实订单付款时间，不使用每日汇总数据推测。";
      return;
    }

    date.textContent = `${shortDateLabel(snapshot.minDate)}—${shortDateLabel(snapshot.maxDate)} · ${integer(snapshot.validOrders)} 笔有效订单`;
    const top = [...snapshot.promotions]
      .sort((left, right) => right.commission - left.commission || right.orders - left.orders)
      .slice(0, 3);

    grid.innerHTML = top.map((promotion, index) => {
      const segment = promotion.segments?.[state.peakSegment] || promotion.segments?.weekday;
      const hours = (segment?.hours || []).map((value) => number(value));
      const peak = { start: segment?.peakStart ?? peakWindow(hours).start, orders: segment?.peakShare ?? 0 };
      const maximum = Math.max(...hours, 1);
      const share = number(segment?.peakShare) * 100;
      const confidence = peakConfidence(segment || { activeDays: 0, orders: 0 });
      const peakHours = new Set([peak.start, (peak.start + 1) % 24]);
      const chartLabel = hours.map((value, hour) => `${hourLabel(hour)} ${(value * 100).toFixed(1)}%`).join("，");
      const latest = promotion.latest || {};
      const latestLabel = latest.date === shanghaiDateKey(-1) ? "昨日" : shortDateLabel(latest.date);
      const latestStatus = latestPeakStatus(latest);
      const comparisonKeys = ["weekday", "weekend", "recent14"];
      return `
        <article class="peak-card peak-rank-${index + 1}">
          <div class="peak-card-head">
            <div><span>TOP ${index + 1}</span><h3>${escapeHtml(promotion.promotion)}</h3></div>
            <em class="confidence ${confidence.tone}">${confidence.label}</em>
          </div>
          <div class="peak-summary">
            <div><small>${segmentLabel(state.peakSegment)} · 连续两小时</small><strong>${hourLabel(peak.start)}—${hourLabel(peak.start + 2)}</strong></div>
            <div><small>高峰订单占比</small><strong>${share.toFixed(1)}%</strong><span>${integer(segment?.activeDays || 0)} 个有单日 · ${integer(segment?.orders || 0)} 单</span></div>
          </div>
          <div class="hour-bars" role="img" aria-label="${escapeHtml(promotion.promotion)}每小时订单：${escapeHtml(chartLabel)}">
            ${hours.map((value, hour) => `
              <i class="${peakHours.has(hour) ? "active" : ""}" style="height:${Math.max(value ? 12 : 3, (value / maximum) * 100)}%" title="${hourLabel(hour)} ${(value * 100).toFixed(1)}%"></i>
            `).join("")}
          </div>
          <div class="hour-axis"><span>00</span><span>06</span><span>12</span><span>18</span><span>24</span></div>
          <div class="peak-comparisons">
            ${comparisonKeys.map((key) => {
              const item = promotion.segments?.[key];
              return `<span class="${key === state.peakSegment ? "selected" : ""}"><small>${segmentLabel(key)}</small><b>${hourLabel(item?.peakStart || 0)}—${hourLabel((item?.peakStart || 0) + 2)}</b></span>`;
            }).join("")}
          </div>
          <div class="peak-latest ${latestStatus.tone}">
            <span>${latestLabel} ${integer(latest.orders || 0)} 单 · 高峰 ${hourLabel(latest.peakStart || 0)}—${hourLabel((latest.peakStart || 0) + 2)}</span>
            <b>${latestStatus.text}</b>
          </div>
          <div class="peak-card-foot">
            <span>31 日合计 ${integer(promotion.orders)} 单 · 佣金 ¥${money(promotion.commission)}</span>
            <b>${peakAdvice(peak.start, confidence.tone)}</b>
          </div>
        </article>
      `;
    }).join("");

    note.innerHTML = `<span>模型口径</span> 历史 ${integer(snapshot.calendarDays)} 天，剔除 ${integer(snapshot.invalidOrdersExcluded)} 笔失效订单。工作日与周末分别按“每日小时占比”计算，并使用 10% 截尾平均形成稳定基线，单日爆量只会触发异常提示；“近期 14 天”使用每日 0.9 衰减权重，更快反映新趋势。收入按“预估结算金额 + 预估激励”排序。`;
  }

  function renderMonthlyComparison() {
    const grid = document.getElementById("monthlyGrid");
    const range = document.getElementById("monthlyRange");
    const badge = document.getElementById("monthlyBadge");
    const note = document.getElementById("monthlyNote");
    if (!grid || !range || !badge || !note) return;

    const totalSources = selectedSources().filter((source) => source.kind === "channel");
    const month = monthContext();
    const current = metricsBetween(totalSources, month.currentStart, month.currentEnd);
    const previous = metricsBetween(totalSources, month.previousStart, month.previousEnd);
    const previousRange = availableDateRange(totalSources, month.previousStart, month.previousEnd);
    const previousComplete = Boolean(previousRange?.start === month.previousStart && previousRange?.end === month.previousEnd);
    const currentAov = current.orders ? current.gmv / current.orders : 0;
    const previousAov = previous.orders ? previous.gmv / previous.orders : 0;

    range.textContent = `${month.currentLabel}截至${shortDateLabel(month.currentEnd)} · ${month.previousLabel}${previousComplete ? "完整月" : "当前可见部分"}`;
    badge.textContent = previousComplete ? "可比口径" : "上月数据部分可见";
    badge.classList.toggle("partial", !previousComplete);

    if (!state.data || !totalSources.length) {
      grid.innerHTML = '<div class="monthly-empty">正在同步月度数据…</div>';
      note.textContent = "月度数据同步完成后将自动显示";
      return;
    }

    const items = [
      ["有效订单", `${integer(current.orders)} 笔`, `${integer(previous.orders)} 笔`, current.orders, previous.orders, "orders"],
      ["成交金额", `¥ ${money(current.gmv)}`, `¥ ${money(previous.gmv)}`, current.gmv, previous.gmv, "gmv"],
      ["预估佣金", `¥ ${money(current.commission)}`, `¥ ${money(previous.commission)}`, current.commission, previous.commission, "commission"],
      ["平均客单价", `¥ ${money(currentAov)}`, `¥ ${money(previousAov)}`, currentAov, previousAov, "aov"],
    ];

    grid.innerHTML = items.map(([label, currentValue, previousValue, currentRaw, previousRaw, tone]) => {
      const change = previousComplete ? comparisonValue(currentRaw, previousRaw) : null;
      return `
        <article class="monthly-card ${tone}">
          <span>${label}</span>
          <div class="month-value"><small>${month.currentLabel}</small><b>${currentValue}</b></div>
          <div class="month-previous">
            <span>${month.previousLabel}${previousComplete ? "" : "可见"} ${previousValue}</span>
            ${change ? `<strong class="comparison-pill ${change.tone}">${change.label}</strong>` : '<em>暂不计算月环比</em>'}
          </div>
        </article>
      `;
    }).join("");

    note.innerHTML = previousComplete
      ? `<strong>月份口径完整：</strong>${month.currentLabel}截至昨日，对比${month.previousLabel}完整月。`
      : `<strong>数据范围说明：</strong>公开接口仅保留近 30 天，${month.previousLabel}目前可见 ${previousRange ? `${shortDateLabel(previousRange.start)}—${shortDateLabel(previousRange.end)}` : "暂无记录"}；为避免误导，暂不展示月环比。`;
  }

  function renderYesterdayComparison() {
    const grid = document.getElementById("yesterdayGrid");
    const range = document.getElementById("yesterdayRange");
    const insight = document.getElementById("yesterdayInsight");
    if (!grid || !range || !insight) return;

    const totalSources = selectedSources().filter((source) => source.kind === "channel");
    const yesterdayKey = shanghaiDateKey(-1);
    const previousKey = shanghaiDateKey(-2);
    const yesterday = comparisonDay(totalSources, yesterdayKey);
    const previous = comparisonDay(totalSources, previousKey);
    const complete = totalSources.length > 0
      && yesterday.available === totalSources.length
      && previous.available === totalSources.length;

    range.textContent = `${shortDateLabel(yesterdayKey)}（昨日） 对比 ${shortDateLabel(previousKey)}（前日）`;

    if (!state.data || !totalSources.length) {
      grid.innerHTML = '<div class="yesterday-empty">正在同步完整自然日数据…</div>';
      insight.innerHTML = '<span class="comparison-dot"></span><p>昨日数据同步完成后将自动显示</p>';
      return;
    }

    const yesterdayAov = yesterday.metrics.orders
      ? yesterday.metrics.gmv / yesterday.metrics.orders
      : 0;
    const previousAov = previous.metrics.orders
      ? previous.metrics.gmv / previous.metrics.orders
      : 0;
    const items = [
      ["有效订单", `${integer(yesterday.metrics.orders)} 笔`, `${integer(previous.metrics.orders)} 笔`, yesterday.metrics.orders, previous.metrics.orders, "orders"],
      ["成交金额", `¥ ${money(yesterday.metrics.gmv)}`, `¥ ${money(previous.metrics.gmv)}`, yesterday.metrics.gmv, previous.metrics.gmv, "gmv"],
      ["预估佣金", `¥ ${money(yesterday.metrics.commission)}`, `¥ ${money(previous.metrics.commission)}`, yesterday.metrics.commission, previous.metrics.commission, "commission"],
      ["平均客单价", `¥ ${money(yesterdayAov)}`, `¥ ${money(previousAov)}`, yesterdayAov, previousAov, "aov"],
    ];

    grid.innerHTML = items.map(([label, value, previousValue, currentRaw, previousRaw, tone]) => {
      const change = comparisonValue(currentRaw, previousRaw);
      return `
        <article class="yesterday-card ${tone}">
          <div class="yesterday-card-top">
            <span>${label}</span>
            <strong class="comparison-pill ${change.tone}">${change.label}</strong>
          </div>
          <b>${value}</b>
          <small>前日 ${previousValue}</small>
        </article>
      `;
    }).join("");

    const orderChange = comparisonValue(yesterday.metrics.orders, previous.metrics.orders);
    const gmvChange = comparisonValue(yesterday.metrics.gmv, previous.metrics.gmv);
    insight.className = `yesterday-insight ${complete ? "complete" : "partial"}`;
    insight.innerHTML = `
      <span class="comparison-dot"></span>
      <p><strong>昨日经营速览：</strong>订单${orderChange.label}，成交金额${gmvChange.label}。</p>
      <small>${complete ? "数据口径完整" : `数据待补齐（${Math.min(yesterday.available, previous.available)}/${totalSources.length} 个渠道）`} · 仅比较两个已结束的完整自然日</small>
    `;
  }

  function renderTrend() {
    const chart = document.getElementById("trendChart");
    const title = document.getElementById("trendTitle");
    if (!chart || !title) return;
    const { totals } = dashboardMetrics();
    title.textContent = `${state.period === "all" ? "近 30 天" : periodOptions.find(([key]) => key === state.period)?.[1]}数据走势`;
    const allDates = Array.from(new Set(totals.flatMap((source) => source.daily.map((row) => row.date))))
      .sort((left, right) => right.localeCompare(left));
    let dates;
    if (state.period === "today") dates = allDates.filter((date) => date === shanghaiDateKey());
    else if (state.period === "yesterday") dates = allDates.filter((date) => date === shanghaiDateKey(-1));
    else if (state.period === "month") dates = allDates.filter((date) => date.startsWith(`${monthKey()}-`));
    else if (state.period === "lastMonth") dates = allDates.filter((date) => date.startsWith(`${monthKey(1)}-`));
    else {
      const days = state.period === "7d" ? 7 : 30;
      dates = allDates.slice(0, days);
    }
    dates.reverse();
    const trend = dates.map((date) => ({
      date,
      value: totals.reduce((sum, source) => {
        const row = source.daily.find((item) => item.date === date);
        return sum + (row?.[state.trendMetric] || 0);
      }, 0),
    }));
    if (!trend.length) {
      chart.innerHTML = '<div class="empty-chart"><b>暂无趋势数据</b><span>当前渠道还没有产生有效订单</span></div>';
      return;
    }
    const maximum = Math.max(...trend.map((item) => item.value), 1);
    const labelInterval = Math.max(1, Math.ceil(trend.length / 8));
    chart.innerHTML = `
      <div class="bar-chart" role="img" aria-label="每日数据柱状趋势图">
        <div class="chart-scale"><span>${compact(maximum)}</span><span>${compact(maximum / 2)}</span><span>0</span></div>
        <div class="bars-area">
          <div class="grid-line top"></div><div class="grid-line middle"></div><div class="grid-line bottom"></div>
          ${trend.map((item, index) => {
            const height = Math.max((item.value / maximum) * 100, item.value ? 4 : 1);
            const label = index % labelInterval === 0 || index === trend.length - 1
              ? item.date.slice(5).replace("-", ".")
              : "";
            return `
              <div class="bar-column" title="${escapeHtml(item.date)}：${item.value}">
                <div class="bar-track">
                  <div class="bar-fill ${state.trendMetric}" style="height:${height}%">
                    ${trend.length <= 7 && item.value > 0 ? `<span>${compact(item.value)}</span>` : ""}
                  </div>
                </div>
                <small>${label}</small>
              </div>
            `;
          }).join("")}
        </div>
      </div>
    `;
  }

  function renderChannels() {
    const list = document.getElementById("channelList");
    const count = document.getElementById("sourceCount");
    const reconcileBox = document.getElementById("reconcileBox");
    if (!list || !count || !reconcileBox) return;
    const allSources = state.data?.sources || [];
    const successful = allSources.filter((source) => source.status === "ok").length;
    count.textContent = `${successful}/${allSources.length || state.config?.sources?.length || 14} 数据源正常`;
    const { visible, current } = dashboardMetrics();
    list.innerHTML = allSources.filter((source) => source.kind === "channel").map((source) => {
      const metrics = metricsFor(source, state.period);
      const share = current.orders && state.channel === "全部"
        ? (metrics.orders / current.orders) * 100
        : metrics.orders ? 100 : 0;
      return `
        <div class="channel-item">
          <div class="channel-icon"><span class="${source.channel === "小红书" ? "xhs-bg" : "wecom-bg"}">${source.channel === "小红书" ? "小" : "企"}</span></div>
          <div class="channel-copy">
            <div><strong>${escapeHtml(source.channel)}</strong><span>${integer(metrics.orders)} 笔</span></div>
            <div class="progress"><i style="width:${Math.max(share, metrics.orders ? 4 : 0)}%"></i></div>
            <small>成交 ¥${money(metrics.gmv)} · 佣金 ¥${money(metrics.commission)}</small>
          </div>
        </div>
      `;
    }).join("");
    const promotions = visible.filter((source) => source.kind === "promotion");
    const promotionMetrics = aggregate(promotions, state.period);
    const reconciled = Math.abs(promotionMetrics.orders - current.orders) < 0.001;
    reconcileBox.innerHTML = `
      <div class="reconcile ${reconciled ? "ok" : "warn"}">
        <span>${reconciled ? "✓" : "!"}</span>
        <div>
          <strong>${reconciled ? "推广位汇总已对齐" : "推广位汇总存在差异"}</strong>
          <small>总数据 ${integer(current.orders)} 笔 / 推广位合计 ${integer(promotionMetrics.orders)} 笔</small>
        </div>
      </div>
    `;
  }

  function promotionRows() {
    const { visible, current } = dashboardMetrics();
    const query = state.search.trim().toLowerCase();
    return visible
      .filter((source) =>
        source.kind === "promotion"
        && (!query || `${source.channel}${source.promotion}`.toLowerCase().includes(query)))
      .map((source) => {
        const metrics = metricsFor(source, state.period);
        const last7 = metricsFor(source, "7d");
        const prior7 = metricsFor(source, "7d", 7);
        return {
          ...source,
          metrics,
          share: current.orders ? (metrics.orders / current.orders) * 100 : 0,
          trend: ratio(last7.orders, prior7.orders),
        };
      })
      .sort((left, right) =>
        right.metrics.orders - left.metrics.orders || right.metrics.gmv - left.metrics.gmv);
  }

  function growthPresentation(current, previous) {
    if (!previous && !current) {
      return { tone: "flat", value: "—", note: "近 14 天暂无订单" };
    }
    if (!previous) {
      return { tone: "new", value: "新增", note: `近 7 天 ${integer(current)} 单` };
    }
    const change = ratio(current, previous) || 0;
    return {
      tone: change > 0 ? "up" : change < 0 ? "down" : "flat",
      value: `${change > 0 ? "↑" : change < 0 ? "↓" : ""} ${Math.abs(change).toFixed(1)}%`.trim(),
      note: `${integer(current)} 单 vs ${integer(previous)} 单`,
    };
  }

  function growthCell(current, previous) {
    const growth = growthPresentation(current, previous);
    return `
      <div class="growth-cell ${growth.tone}">
        <strong>${growth.value}</strong>
        <small>${growth.note}</small>
      </div>
    `;
  }

  function periodGrowthCell(source) {
    if (state.period === "today") {
      return growthCell(metricsFor(source, "today").orders, metricsFor(source, "today", 1).orders);
    }
    if (state.period === "yesterday") {
      return growthCell(metricsFor(source, "yesterday").orders, metricsFor(source, "today", 2).orders);
    }
    if (state.period === "month") {
      return `<div class="growth-cell flat"><strong>本月累计</strong><small>${integer(metricsFor(source, "month").orders)} 单</small></div>`;
    }
    if (state.period === "lastMonth") {
      const { totals } = dashboardMetrics();
      const complete = completeMonthAvailable(totals, 1);
      const comparable = complete && completeMonthAvailable(totals, 2);
      if (comparable) {
        return growthCell(metricsFor(source, "lastMonth").orders, metricsFor(source, "lastMonth", 1).orders);
      }
      return `<div class="growth-cell flat"><strong>${complete ? "上月累计" : "上月可见"}</strong><small>${integer(metricsFor(source, "lastMonth").orders)} 单</small></div>`;
    }
    return growthCell(metricsFor(source, "7d").orders, metricsFor(source, "7d", 7).orders);
  }

  function detailPeriodLabel() {
    if (state.period === "all") return "累计概览 · 每日明细展示近 30 天";
    return `${periodOptions.find(([key]) => key === state.period)?.[1] || "当前周期"}明细`;
  }

  function closePromotionDetail() {
    const overlay = document.getElementById("promotionDetail");
    if (!overlay) return;
    document.body.classList.remove("modal-open");
    overlay.remove();
  }

  function openPromotionDetail(sourceId) {
    closePromotionDetail();
    const source = (state.data?.sources || []).find(
      (item) => item.id === sourceId && item.kind === "promotion",
    );
    if (!source) return;
    const metrics = metricsFor(source, state.period);
    const current7 = metricsFor(source, "7d");
    const previous7 = metricsFor(source, "7d", 7);
    const growth = growthPresentation(current7.orders, previous7.orders);
    const daily = state.period === "all"
      ? dailyRowsForPeriod(source, "30d")
      : dailyRowsForPeriod(source, state.period);
    const dailyRows = daily.length
      ? daily.map((row, index) => {
        const previous = daily[index + 1];
        const dailyChange = previous ? ratio(row.orders, previous.orders) : null;
        const changeText = dailyChange === null
          ? "—"
          : `${dailyChange > 0 ? "↑" : dailyChange < 0 ? "↓" : ""} ${Math.abs(dailyChange).toFixed(1)}%`.trim();
        const changeTone = dailyChange > 0 ? "up" : dailyChange < 0 ? "down" : "flat";
        return `
          <tr>
            <td>${escapeHtml(row.date)}</td>
            <td><b>${integer(row.orders)}</b></td>
            <td>¥ ${money(row.gmv)}</td>
            <td>¥ ${money(row.commission)}</td>
            <td>¥ ${row.orders ? money(row.gmv / row.orders) : "0.00"}</td>
            <td><span class="daily-change ${changeTone}">${changeText}</span></td>
          </tr>
        `;
      }).join("")
      : '<tr><td colspan="6"><div class="detail-empty">当前周期暂无每日明细</div></td></tr>';
    const overlay = document.createElement("div");
    overlay.id = "promotionDetail";
    overlay.className = "detail-overlay";
    overlay.innerHTML = `
      <section class="detail-dialog" role="dialog" aria-modal="true" aria-labelledby="detailTitle">
        <header class="detail-head">
          <div class="detail-identity">
            <span class="${source.channel === "小红书" ? "xhs-bg" : "wecom-bg"}">${source.channel === "小红书" ? "小" : "企"}</span>
            <div>
              <p>${escapeHtml(source.channel)} · ${detailPeriodLabel()}</p>
              <h2 id="detailTitle">${escapeHtml(source.promotion)}</h2>
            </div>
          </div>
          <button class="detail-close" type="button" aria-label="关闭详细数据">×</button>
        </header>
        <div class="detail-summary">
          <article><span>有效订单</span><strong>${integer(metrics.orders)} 笔</strong></article>
          <article><span>成交金额</span><strong>¥ ${money(metrics.gmv)}</strong></article>
          <article><span>预估佣金</span><strong>¥ ${money(metrics.commission)}</strong></article>
          <article><span>平均客单价</span><strong>¥ ${metrics.orders ? money(metrics.gmv / metrics.orders) : "0.00"}</strong></article>
        </div>
        <div class="detail-growth">
          <div>
            <span>近 7 天增长趋势</span>
            <strong class="${growth.tone}">${growth.value}</strong>
          </div>
          <small>${growth.note} · 对比前 7 天</small>
        </div>
        <div class="detail-table-wrap">
          <table class="detail-table">
            <thead>
              <tr><th>日期</th><th>有效订单</th><th>成交金额</th><th>预估佣金</th><th>客单价</th><th>日环比</th></tr>
            </thead>
            <tbody>${dailyRows}</tbody>
          </table>
        </div>
        <footer class="detail-actions">
          <span>每日数据按日期从新到旧排列</span>
          <a href="${escapeHtml(safeExternalUrl(source.shortUrl))}" target="_blank" rel="noopener noreferrer">打开原始看板 ↗</a>
        </footer>
      </section>
    `;
    document.body.appendChild(overlay);
    document.body.classList.add("modal-open");
    const onEscape = (event) => {
      if (event.key === "Escape") dismiss();
    };
    const dismiss = () => {
      document.removeEventListener("keydown", onEscape);
      closePromotionDetail();
    };
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay || event.target.closest(".detail-close")) {
        dismiss();
      }
    });
    document.addEventListener("keydown", onEscape);
    overlay.querySelector(".detail-close")?.focus();
  }

  function renderRanking() {
    const body = document.getElementById("rankingBody");
    if (!body) return;
    const rows = promotionRows();
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="10"><div class="table-empty">没有找到匹配的推广位</div></td></tr>';
      return;
    }
    body.innerHTML = rows.map((row, index) => {
      return `
        <tr>
          <td><span class="rank-number rank-${index + 1}">${String(index + 1).padStart(2, "0")}</span></td>
          <td>
            <div class="promotion-name">
              <span class="${row.channel === "小红书" ? "xhs-bg" : "wecom-bg"}">${row.channel === "小红书" ? "小" : "企"}</span>
              <div><strong>${escapeHtml(row.promotion)}</strong><small>${escapeHtml(row.channel)}</small></div>
            </div>
          </td>
          <td><b>${integer(row.metrics.orders)}</b></td>
          <td>¥ ${money(row.metrics.gmv)}</td>
          <td>¥ ${money(row.metrics.commission)}</td>
          <td><span class="commission-rate" title="预估佣金 ÷ 成交金额">${row.metrics.gmv ? `${((row.metrics.commission / row.metrics.gmv) * 100).toFixed(2)}%` : "—"}</span></td>
          <td>¥ ${row.metrics.orders ? money(row.metrics.gmv / row.metrics.orders) : "0.00"}</td>
          <td>
            <div class="share-cell"><span>${row.share.toFixed(1)}%</span><i><em style="width:${Math.min(row.share, 100)}%"></em></i></div>
          </td>
          <td>${periodGrowthCell(row)}</td>
          <td><button class="detail-trigger" type="button" data-detail-id="${escapeHtml(row.id)}">查看详情</button></td>
        </tr>
      `;
    }).join("");
  }

  async function bootstrap() {
    const form = document.getElementById("passwordForm");
    form?.addEventListener("submit", (event) => {
      event.preventDefault();
      const input = document.getElementById("dashboard-password");
      const password = input?.value.trim();
      if (!password) {
        setLoginStatus("请输入访问密码", true);
        return;
      }
      void unlockWithPassword(password);
    });
    setLoginBusy(true);
    setLoginStatus("正在加载安全配置…");
    try {
      state.bundle = await loadBundle();
      const savedKey = await restoreAccessKey(state.bundle);
      if (savedKey) {
        try {
          state.config = await decryptBundle(state.bundle, savedKey);
          state.key = savedKey;
          showDashboard();
          return;
        } catch {
          await vaultDelete(KEY_RECORD);
        }
      }
      setLoginStatus("");
    } catch (error) {
      setLoginStatus(error instanceof Error ? error.message : "页面暂时无法加载", true);
    } finally {
      setLoginBusy(false);
    }
  }

  void bootstrap();
})();
