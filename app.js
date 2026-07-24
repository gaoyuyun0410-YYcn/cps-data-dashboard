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
    ["7d", "近 7 天"],
    ["30d", "近 30 天"],
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

          <aside class="panel channel-panel">
            <div class="panel-head compact-head">
              <div>
                <p class="panel-kicker">渠道对比</p>
                <h2>渠道贡献</h2>
              </div>
              <span class="source-count" id="sourceCount">0/12 数据源正常</span>
            </div>
            <div class="channel-list" id="channelList"></div>
            <div id="reconcileBox"></div>
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
                  <th>预估佣金</th><th>客单价</th><th>订单贡献</th><th>状态</th><th>原始看板</th>
                </tr>
              </thead>
              <tbody id="rankingBody"></tbody>
            </table>
          </div>
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
    document.getElementById("promotionSearch")?.addEventListener("input", (event) => {
      state.search = event.target.value;
      renderRanking();
    });
    document.getElementById("refreshButton")?.addEventListener("click", () => {
      void refreshData();
    });
  }

  const zeroMetrics = () => ({ orders: 0, commission: 0, gmv: 0 });

  function addMetrics(target, value) {
    target.orders += value.orders;
    target.commission += value.commission;
    target.gmv += value.gmv;
    return target;
  }

  function metricsFor(source, period, offset = 0) {
    if (period === "all") return offset === 0 ? { ...source.totals } : zeroMetrics();
    const days = period === "today" ? 1 : period === "7d" ? 7 : 30;
    return source.daily
      .slice(offset, offset + days)
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
    const offset = state.period === "today" ? 1 : state.period === "7d" ? 7 : 0;
    const previous = state.period === "all" || state.period === "30d"
      ? zeroMetrics()
      : aggregate(totals, state.period, offset);
    return { visible, totals, current, previous };
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
    renderError();
    renderKpis();
    renderTrend();
    renderChannels();
    renderRanking();
    setSyncState();
  }

  function renderError() {
    const banner = document.getElementById("errorBanner");
    if (!banner) return;
    banner.textContent = state.error;
    banner.classList.toggle("hidden", !state.error);
  }

  function renderKpis() {
    const grid = document.getElementById("kpiGrid");
    if (!grid) return;
    const { current, previous } = dashboardMetrics();
    const canCompare = state.period === "today" || state.period === "7d";
    const compareLabel = state.period === "today" ? "较昨日" : "较前 7 天";
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
        : '<span class="neutral">按当前筛选范围统计</span>';
      return `
        <article class="kpi-card ${tone}">
          <div class="kpi-heading"><span>${label}</span><i aria-hidden="true"></i></div>
          <strong>${state.loading && !state.data ? "—" : value}</strong>
          <div class="kpi-foot">${comparisonHtml}</div>
        </article>
      `;
    }).join("");
  }

  function renderTrend() {
    const chart = document.getElementById("trendChart");
    const title = document.getElementById("trendTitle");
    if (!chart || !title) return;
    const { totals } = dashboardMetrics();
    const days = state.period === "today" ? 1 : state.period === "7d" ? 7 : 30;
    title.textContent = `${state.period === "all" ? "近 30 天" : periodOptions.find(([key]) => key === state.period)?.[1]}数据走势`;
    const dates = Array.from(new Set(totals.flatMap((source) => source.daily.map((row) => row.date))))
      .sort((left, right) => right.localeCompare(left))
      .slice(0, days)
      .reverse();
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
    count.textContent = `${successful}/${allSources.length || 12} 数据源正常`;
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

  function renderRanking() {
    const body = document.getElementById("rankingBody");
    if (!body) return;
    const rows = promotionRows();
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="9"><div class="table-empty">没有找到匹配的推广位</div></td></tr>';
      return;
    }
    body.innerHTML = rows.map((row, index) => {
      const status = row.metrics.orders === 0
        ? "待启动"
        : row.trend !== null && row.trend > 0 ? "增长中" : "有转化";
      const statusClass = status === "增长中" ? "growth" : status === "待启动" ? "idle" : "active";
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
          <td>¥ ${row.metrics.orders ? money(row.metrics.gmv / row.metrics.orders) : "0.00"}</td>
          <td>
            <div class="share-cell"><span>${row.share.toFixed(1)}%</span><i><em style="width:${Math.min(row.share, 100)}%"></em></i></div>
          </td>
          <td><span class="status-pill ${statusClass}">${status}</span></td>
          <td><a href="${escapeHtml(safeExternalUrl(row.shortUrl))}" target="_blank" rel="noopener noreferrer">查看 ↗</a></td>
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
